# Active Checks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `hx` probe — the first checks that send requests, the runner pass that drives them, and the contract change that lets a check retire a finding it no longer sees.

**Architecture:** `scan.run` dispatches on which runner-called hook a check implements: passive checks keep `on_surface`, active checks get a new `probes` hook handed derived insertion points and a bounded sender. The sender wraps `bridge.send()`, so every byte still leaves through the extension and §4's enforcement invariant needs no new argument — there are **no Java changes in this plan**. `Verdict` gains a `considered` set so the runner can retire a finding whose issue type was examined and not re-emitted.

**Tech Stack:** Python 3.12, `.venv/bin/pytest`, click CLI, sqlite3. Zero new third-party dependencies.

**Spec:** `docs/superpowers/specs/2026-08-28-active-checks-design.md` (approved 2026-08-28)

**What changed under this plan while it waited.** This plan was drafted before the bridge
session existed and was blocked on it. That plan has since merged (`537bc5a`), so
`src/hx/session.py` now provides `session(eng, *, instance, jar=None, workdir=None)`, a
context manager yielding `LiveSession(operator_port, crawler_port, epoch, bridge, workdir)`
with a live, loopback-verified, **authorised** Burp. That answers this plan's hardest open
question — where `hx scan` gets a bridge — and Task 7 wires it. `hx scan` opens a session
**only when an active check class is enabled**: a passive-only scan stays offline and must
not pay Burp's startup.
**Master spec:** `docs/superpowers/specs/2026-08-21-hx-design.md` (§4 enforcement invariant, §5 tables, §10 check classes, §12 reporting, §13 v1 scope)

## Global Constraints

- **§4 enforcement invariant:** every byte that leaves this machine crosses one of two points inside the JVM — the send path or the proxy request handler. DENY-ALL is terminal. A check never owns a socket; it is handed a sender it cannot construct.
- **No Java changes.** `extension/` is untouched. `./extension/test.sh` must still print `13 ALL PASS`, 2330 `ok`, ~2352 output lines, rc 0. Check the **line count**, not just rc — it has printed zero summary lines and exited 0 with a missing jar.
- **§12's governing rule:** a report that cannot distinguish "tested, clean" from "never reached" is worse than no report.
- **§10:** a check that cannot run returns `inconclusive(reason)` — **never `clean`**.
- **Methods are GET/HEAD/OPTIONS only.** `Policy.DEFAULT_METHODS`; Python's `Config` has no `method` key and this plan does not add one. `body_form` and `body_json` insertion points stay derived, recorded, and unprobed.
- **All test targets are loopback only.** Nothing in this project has ever sent a request off this machine, and no test may be the first. Never run Burp against the real `$HOME` — the integration fixture builds a private home per run; do not work around it.
- **The agent may never write finding status `confirmed` or `reported`** (DB trigger enforces it).
- Engagement directories `0o700`; blob and DB files `0o600`. Never looser, never widened.
- **Baselines at the time of writing:** `.venv/bin/pytest` → `1006 passed, 1 skipped, 32 deselected`; `.venv/bin/pytest -m integration` → `32 passed` (~210s, real headless Burp); `./extension/test.sh` → `13 ALL PASS`, 2330 `ok`, 2352 output lines, rc 0.
- **Never trust a cumulative total written in this plan.** The previous plan's arithmetic was wrong four times, and an implementer who trusts a stale total either "fixes" a passing suite to match it or reports a false regression. **Measure the suite before you start, add your task's tests, and report the delta you actually observed.** The numbers above are the state when this plan was written and nothing more.
- Some functions are guarded by plan byte-compare tests. If one breaks, sync it with a trailing `chore(plans):` commit — see `13a029e` and `3fc0a41` for the established pattern.
- **Markers go on at the END, not during execution.** `tests/test_plan_matches_repo.py` compares a marked block against the file it names, so a marker added before the code exists fails on every run — which is what happened when this plan was first committed. During execution the blocks stay unmarked. **The last task adds `# path` markers to every block meant to be transcribed verbatim and syncs them with `scripts/sync_plan_block.py`**, once the code they describe exists.
- When you do mark them: **code blocks meant to be transcribed verbatim carry a `# path` marker on their first line** — `path` for a whole file, `path -- note` for an excerpt — so `tests/test_plan_matches_repo.py` holds them against the repo. The previous plan shipped with **zero** compared blocks, because one block was restructured mid-flight to dodge a marker error and nobody noticed until the whole-branch review counted them. **An unmarked block is silently never compared.** Blocks that are deliberately sketches (test shapes an implementer will adapt to existing fixtures) are left unmarked AND say so in their surrounding prose, so the distinction is stated rather than inferred from an absent comment.
- **`tests/test_plan_matches_repo.py` reddens on ANY edit to a file it covers**, correct or not. It is never evidence that a behaviour is pinned. When you mutate something to check a test bites, look at WHICH test failed and disregard that one.
- **Verifying a restored file with `sha256sum` is not sufficient on this machine.** A mutation that is byte-length-identical to the original can leave a stale `.pyc` that passes CPython's mtime+size check, and the suite will run the mutant after a clean checksum. Clear `__pycache__` after every restore, then re-verify.

---

## File Structure

**Created:**
- `src/hx/checks/probe.py` — the send seam. `ProbeSender` (counts in memory, raises on refusal), `ProbeResponse`, `ProbeRefused`. One responsibility: turn a check's intent to send into an enforced request, and turn any refusal into something a check cannot mistake for an answer.
- `src/hx/checks/active/__init__.py` — package marker.
- `src/hx/checks/active/_probe_util.py` — canary minting and the reflection test, shared by the three checks that send a value and match the response (reflected input, SQL error, path traversal). CORS and open redirect do not mint canaries and must not import it.
- `src/hx/checks/active/cors.py`, `open_redirect.py`, `reflected_input.py`, `sql_error.py`, `path_traversal.py` — one file per check, matching `checks/passive/`'s layout.

**Modified:**
- `src/hx/checks/base.py` — `Verdict.considered`; amend the module docstring, which currently says a check "does not build requests… or reach the bridge".
- `src/hx/scan.py` — the probe pass, hook dispatch, `requests_sent` at row close, retirement change in `_mark_unobserved`.
- `src/hx/checks/registry.py` — `"probes"` joins `_RUNNER_CALLS`.
- `src/hx/checks/passive/_http.py` — bare-LF header parsing.
- `src/hx/checks/passive/{cookie_flags,security_headers,secret_in_response,stack_trace}.py` — populate `considered`.
- `src/hx/config.py` — `max_requests`.
- `src/hx/cli.py` — `--max-requests`; `scan` acquires a bridge when active checks are enabled.
- `src/hx/report.py` — insertion coverage, unshipped-class note, derived Limits prose.
- `tests/integration/target_server.py` — probeable endpoints.

---

## Task 1: `Verdict.considered` and the contract amendment

**Files:**
- Modify: `src/hx/checks/base.py`
- Test: `tests/test_checks_base.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `Verdict.considered: tuple[str, ...]`; `Verdict.clean(*, considered=())`; `Verdict.finding(*candidates, considered=())`. `Verdict.inconclusive(reason)` is **unchanged and takes no `considered`** — a check that could not run concluded nothing and must not retire anything.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_checks_base.py -- Task 1: what a verdict may say it considered
def test_a_clean_verdict_can_name_what_it_considered():
    v = base.Verdict.clean(considered=("missing-hsts", "missing-xcto"))
    assert v.state == "clean"
    assert v.considered == ("missing-hsts", "missing-xcto")


def test_a_finding_verdict_can_name_what_it_considered(a_candidate):
    v = base.Verdict.finding(a_candidate, considered=("missing-hsts",))
    assert v.considered == ("missing-hsts",)


def test_a_finding_verdict_that_names_nothing_considered_retires_nothing(a_candidate):
    # The safe default for `finding()` is the same as for `clean()`: an empty
    # `considered`. Two failure directions are possible for this default, and
    # only one of them is acceptable -- an empty default leaves a finding
    # live (safe: nothing is retired that wasn't examined), while a default
    # DERIVED from the emitted candidates' own issue types would retire
    # every OTHER issue type the check never looked at (unsafe: a check
    # emitting one of three candidates would silently close the other two,
    # telling a client a still-open issue is fixed because the check merely
    # stopped finding it, not because it looked and confirmed it gone).
    assert base.Verdict.finding(a_candidate).considered == ()


def test_considered_defaults_to_empty_so_an_unaware_check_retires_nothing():
    # The failure mode of a check that never populates `considered` must be a
    # finding staying live, never a finding falsely closed.
    assert base.Verdict.clean().considered == ()


def test_inconclusive_cannot_name_considered_issue_types():
    # S10: a check that cannot run says so. It concluded nothing, so it may
    # not retire anything -- the classmethod does not offer the argument.
    with pytest.raises(TypeError):
        base.Verdict.inconclusive("bridge_lost", considered=("missing-hsts",))


def test_considered_must_be_a_tuple_of_non_empty_strings():
    with pytest.raises(ValueError):
        base.Verdict("clean", (), None, ("",))
    with pytest.raises(ValueError):
        base.Verdict("clean", (), None, ("ok", 3))
```

- [ ] **Step 2: Run them to verify they fail**

Run: `.venv/bin/pytest tests/test_checks_base.py -k considered -v`
Expected: FAIL — `Verdict.clean() got an unexpected keyword argument 'considered'`.

- [ ] **Step 3: Add the field and validation**

In `src/hx/checks/base.py`, add to `Verdict` after `reason`:

```python
# src/hx/checks/base.py -- Task 1: the considered field
    # What this check EXAMINED on this subject and reached a conclusion about,
    # as `issue_type_id` strings. `hx.scan._mark_unobserved` retires a finding
    # whose issue type is in here and was NOT re-emitted this run.
    #
    # It exists because the retirement gate it replaces was sound only while a
    # check filed at most ONE finding per surface. `issue_type_id` (F1 of Plan
    # 5's whole-branch review) made N-per-surface the norm, and a check that
    # finds one of three issues answers `finding` -- so under the old
    # clean-only gate the other two were never retired and rendered live off
    # stale observations, telling a client a fixed issue was still open.
    #
    # RUN-TIME, NOT DECLARED. A class-level list cannot express
    # `hx.checks.passive.cookie_flags`, which mints an issue type per cookie
    # NAME; what it considered is whatever cookies this surface actually set.
    #
    # DEFAULTS EMPTY, AND THAT IS THE SAFE DIRECTION: a check that populates
    # nothing retires nothing. The failure mode is a finding staying live,
    # never one falsely closed.
    #
    # PASSIVE CHECKS ONLY, SINCE FIX ROUND 6, AND THE RUNNER ENFORCES IT.
    # `hx.scan._retirable` returns nothing for a check driven through the
    # `probes` hook and RAISES if such a check populated this at all: every
    # probe this build sends is unauthenticated, so an active check's
    # conclusion is about the logged-out view of the application and cannot
    # close a finding about the view the client's users are in. An active
    # check names what it examined to `hx.checks.active._probe_util.verdict`
    # as `examined` instead -- which is what lets it say `clean` -- and that
    # value deliberately never reaches this field. See `_retirable` for the
    # argument and for the two narrower rules that were tried first.
    considered: tuple[str, ...] = ()
```

Add to `__post_init__`, after the existing checks:

```python
# src/hx/checks/base.py -- Task 1: considered is validated like every other field
        for issue_type in self.considered:
            if not isinstance(issue_type, str) or not issue_type:
                raise ValueError(
                    f"considered holds {issue_type!r}; it is a tuple of "
                    "issue_type_id strings, and a blank or non-string entry "
                    "would retire a finding nothing can be matched against")
```

Replace the two classmethods (leave `inconclusive` exactly as it is):

```python
# src/hx/checks/base.py -- Task 1: clean() and finding() carry it, inconclusive does not
    @classmethod
    def clean(cls, *, considered: tuple[str, ...] = ()) -> "Verdict":
        return cls("clean", (), None, tuple(considered))

    @classmethod
    def finding(cls, *candidates: Candidate,
                considered: tuple[str, ...] = ()) -> "Verdict":
        return cls("finding", tuple(candidates), None, tuple(considered))
```

- [ ] **Step 4: Amend the module docstring, which is now false**

The first paragraph of `src/hx/checks/base.py` reads "A check is pure. It reads a surface and the exchanges captured against it and returns a verdict. It does not build requests, write rows, compute dedupe keys, learn its own `check_run` id, or reach the bridge". An active check builds requests. Replace that paragraph with:

```python
# src/hx/checks/base.py -- Task 1: the module docstring an active check made false
"""The types a check speaks in, and the ones it deliberately cannot.

A PASSIVE check is pure: it reads a surface and the exchanges captured
against it and returns a verdict. An ACTIVE check additionally builds
requests -- but it does not own a socket, and cannot construct one. It is
handed a `hx.checks.probe.ProbeSender` by the runner, which is the only
route to the wire and which enforces S4 by going through the extension
like everything else.

What NO check does, active or passive: write rows, compute dedupe keys,
learn its own `check_run` id, or hold a database connection. Each of those
belongs to the runner, and each is a place where ONE implementation must
serve every check or the guarantees stop being uniform.
```

- [ ] **Step 5: Run the whole suite**

Run: `.venv/bin/pytest -q`
Expected: the baseline you recorded at the start of this task, plus the tests you added.
Report the line you actually saw. (When this plan was written the arithmetic here would have been `936`; treat that as stale unless it matches what you measured.)

- [ ] **Step 6: Commit**

```bash
git add src/hx/checks/base.py tests/test_checks_base.py
git commit -m "feat(checks): Verdict carries what the check considered"
```

---

## Task 2: retire what was considered and not re-emitted

**Files:**
- Modify: `src/hx/scan.py` (`_mark_unobserved`)
- Test: `tests/test_scan.py`

**Interfaces:**
- Consumes: `Verdict.considered` from Task 1.
- Produces: `scan.run` collects `(surface_id, check_id, issue_type_id)` triples from every verdict it accepts and passes them to `_mark_unobserved`, which retires findings on that basis instead of on a `clean` check_run row.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_scan.py -- Task 2: retirement follows examination, not absence
def test_a_check_retires_the_one_issue_it_no_longer_finds(scan_env):
    """The defect this task exists for.

    A check that finds one of three issues answers `finding`, so the
    clean-only gate never fired and the two fixed issues rendered live off
    their stale run-1 observations, with no "appears fixed" marker.
    """
    def _candidate(ctx, exchanges, issue_type_id):
        return base.Candidate(
            title=f"t-{issue_type_id}", issue_type_id=issue_type_id,
            severity="Low", confidence="Firm", insertion=None,
            exchange_ids=(exchanges[0].id,))

    class Finds:
        id, version, klass = "hx.test.three", "1", "passive"
        insertion_kinds = frozenset()

        def __init__(self):
            self.emit = ("a", "b", "c")

        def on_surface(self, ctx, surface_row, exchanges):
            return base.Verdict.finding(
                *[_candidate(ctx, exchanges, t) for t in self.emit],
                considered=("a", "b", "c"))

    check = Finds()
    scan.run(**scan_env, checks=(check,))
    check.emit = ("a",)                      # b and c are fixed
    scan.run(**scan_env, checks=(check,))

    conn = scan_env["conn"]
    observed = dict(conn.execute(
        "SELECT f.issue_type_id, o.observed FROM finding f"
        " JOIN finding_observation o ON o.finding_id = f.id"
        " WHERE o.run_id = (SELECT id FROM run ORDER BY started_us DESC"
        "                   LIMIT 1)").fetchall())
    assert observed == {"a": 1, "b": 0, "c": 0}


def test_an_issue_type_the_check_never_considered_is_not_retired(scan_env):
    """The separating case. Retirement must follow examination, not absence.

    A check that stops looking at something has not established it is fixed,
    and a report that closed a finding on that basis would be inventing a
    fact the run does not hold.
    """
    def _candidate(ctx, exchanges, issue_type_id):
        return base.Candidate(
            title=f"t-{issue_type_id}", issue_type_id=issue_type_id,
            severity="Low", confidence="Firm", insertion=None,
            exchange_ids=(exchanges[0].id,))

    class Narrows:
        id, version, klass = "hx.test.narrow", "1", "passive"
        insertion_kinds = frozenset()

        def __init__(self):
            self.considered = ("a", "b")

        def on_surface(self, ctx, surface_row, exchanges):
            emit = [t for t in ("a", "b") if t in self.considered]
            return base.Verdict.finding(
                *[_candidate(ctx, exchanges, t) for t in emit],
                considered=self.considered)

    check = Narrows()
    scan.run(**scan_env, checks=(check,))
    check.considered = ("a",)                # b is no longer examined at all
    scan.run(**scan_env, checks=(check,))

    conn = scan_env["conn"]
    rows = conn.execute(
        "SELECT o.observed FROM finding f"
        " JOIN finding_observation o ON o.finding_id = f.id"
        " WHERE f.issue_type_id='b' ORDER BY o.ts_us").fetchall()
    assert [r[0] for r in rows] == [1], (
        "an unexamined issue type was retired: the report would tell a client "
        "an issue is fixed on the strength of the check having stopped looking")
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_scan.py -k "retires_the_one_issue or never_considered" -v`
Expected: first FAILS with `{'a': 1}` (b and c absent — no observation row written at all).

- [ ] **Step 3: Collect considered triples in `scan.run`**

In `scan.run`, beside `seen_findings: set[str] = set()`, add:

```python
# src/hx/scan.py -- Task 2: the considered set the runner collects
        # (surface_id, check_id, issue_type_id) this run examined AND may
        # speak for the client's own view of. Retirement reads this, NOT
        # `check_run.verdict == 'clean'`: a check filing one of three
        # findings answers `finding`, and the other two still need retiring.
        # The second clause is `_retirable`'s and it is why nothing an
        # ACTIVE check said can be in here: every probe this build sends is
        # unauthenticated, so what it saw is not necessarily the view the
        # client's users are in.
        considered: set[tuple[str, str, str]] = set()
```

After the `isinstance(verdict, base.Verdict)` guard and before the
`verdict.state == "finding"` branch, add:

```python
# src/hx/scan.py -- Task 2: every accepted verdict contributes to it
                    reason = verdict.reason
                    # An `inconclusive` verdict carries no `considered` -- the
                    # classmethod does not offer it -- so this loop is empty
                    # for exactly the state that must retire nothing, and
                    # `_retirable` empties it for every check the runner
                    # drove through the wire. The verdict itself is not
                    # touched either way: a `finding` is still written and
                    # still reported, a `clean` is still `clean`, and what
                    # `report._coverage` renders for the row is unchanged.
                    for issue_type in _retirable(hook, verdict):
                        considered.add((surface[0], check.id, issue_type))
```

Change the call at the end of the run from `_mark_unobserved(conn, engagement_id, run_id, seen_findings)` to:

```python
# src/hx/scan.py -- Task 2: the call at the end of the run
        _mark_unobserved(conn, engagement_id, run_id, seen_findings, considered)
```

- [ ] **Step 4: Rewrite `_mark_unobserved`'s gate**

Replace the `clean` query and the `(surface_id, check_id) not in clean` filter with a `considered` lookup. The function becomes:

```python
# src/hx/scan.py -- Task 2: _mark_unobserved's new gate
def _mark_unobserved(conn, engagement_id, run_id, seen, considered) -> None:
    """`observed = 0` for a finding whose issue type was EXAMINED this run and
    not re-emitted.

    THE GATE THIS REPLACES was `check_run.verdict == 'clean'` for the
    finding's own (surface, check). That was sound while a check filed at most
    one finding per surface: "the check ran and found nothing" and "this
    finding is gone" were the same sentence. `issue_type_id` made
    N-per-surface the norm, and they stopped being the same sentence -- a
    check finding one of three issues answers `finding`, so the two fixed ones
    were never retired and rendered live off stale observations. A client was
    told a fixed issue was still open.

    EXAMINATION, NOT ABSENCE. A finding is retired only if its issue type is
    in `considered` -- the check looked and did not find it. A check that
    simply stopped looking retires nothing, because "I did not examine this"
    is not evidence of a fix, and S12 forbids rendering the second as the
    first.

    `considered` is built by `scan.run` from every accepted `Verdict`'s own
    `considered` field (Task 1), keyed `(surface_id, check_id, issue_type_id)`.
    An `inconclusive` verdict contributes nothing to it -- the classmethod
    does not accept `considered` at all -- so a check that raised, went
    inconclusive, was skipped by the budget, or was simply absent from this
    run's `checks` retires none of its prior findings: none of those states
    ever added an entry for them.

    AND SINCE FIX ROUND 6, ONLY A PASSIVE CHECK EVER GETS INTO IT.
    `scan.run` reads `_retirable`, which returns nothing for a check driven
    through the wire: every probe this build sends is unauthenticated, so an
    active `clean` is a statement about the logged-out view and not about
    the one the client's users are in. That function carries the argument
    and the two spellings the branch tried before it. So "in `considered`"
    means "examined, by a check that read the captured traffic itself", and
    that is the only reading under which retirement is sound today.

    Row G, spec S8: a surface can vanish between capture and scan. MEASURED:
    the schema's own FK (`finding.surface_id REFERENCES surface(id)`) refuses
    a plain `DELETE FROM surface` the instant anything depends on the row --
    `tests/test_scan.py::test_a_surface_deleted_between_capture_and_scan_is_refused_by_the_schema`
    pins that. Reaching this case at all needs `PRAGMA foreign_keys=OFF`
    around the delete, the shape a bulk purge/retention job takes. Once it
    happens, `considered` is built from THIS run's own surface loop -- a
    vanished surface never appears in it, so it is simply absent, never
    looked up, never guessed about.
    """
    if not considered:
        return
    # `finding.check_id` and `finding.issue_type_id` are different axes (see
    # schema.sql): `check_id` answers "which of hx's checks found this",
    # `issue_type_id` answers "what kind of issue is this", and both are read
    # here because `considered` is keyed on both --
    # `tests/test_scan.py::test_mark_unobserved_reads_check_id_not_issue_type_id`
    # pins that a swap of the two columns must not let this match wrongly.
    rows = conn.execute(
        "SELECT id, surface_id, check_id, issue_type_id FROM finding"
        " WHERE engagement_id=?", (engagement_id,)).fetchall()
    at = now_us()
    with db_mod.transaction(conn):
        for fid, surface_id, check_id, issue_type_id in rows:
            if fid in seen:
                continue
            if (surface_id, check_id, issue_type_id) not in considered:
                continue
            records.record_observation(
                conn, finding_id=fid, run_id=run_id, observed=False,
                exchange_id=None, severity_at=None, confidence_at=None,
                at_us=at)
```

- [ ] **Step 5: Run the suite**

Run: `.venv/bin/pytest -q`
Expected: the baseline you recorded at the start of this task, plus the tests you added.
Report the line you actually saw. (When this plan was written the arithmetic here would have been `938`; treat that as stale unless it matches what you measured.)

Some existing `_mark_unobserved` tests assert the old clean-only behaviour. Read each failure before touching it: a test whose synthetic check returns `Verdict.clean()` with no `considered` now correctly retires nothing. Update those checks to populate `considered` — **do not weaken the assertion.**

- [ ] **Step 6: Commit**

```bash
git add src/hx/scan.py tests/test_scan.py
git commit -m "fix(scan): retire what a check considered, not what it called clean"
```

---

## Task 3: the passive corpus populates `considered`

**Files:**
- Modify: `src/hx/checks/passive/_http.py` (`verdict`), and all four checks in `src/hx/checks/passive/`
- Test: `tests/test_checks_passive.py`

**Interfaces:**
- Consumes: `Verdict.clean(*, considered=())` / `Verdict.finding(*candidates, considered=())` (Task 1).
- Produces: `_http.verdict(evidence, candidates, *, considered=())`. Every passive check passes the issue types it examined.

`_http.verdict` is the corpus's single verdict-construction point, so `considered` threads through one function rather than four.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_checks_passive.py -- Task 3: what security-headers examined, and what an inconclusive verdict did not
def test_security_headers_reports_every_header_it_examined():
    c = security_headers.SecurityHeaders()
    blob = resp(b"Content-Type: text/html",
                b"Strict-Transport-Security: max-age=31536000",
                b"X-Content-Type-Options: nosniff",
                b"X-Frame-Options: DENY")
    v = c.on_surface(ctx_for(d1=blob), None, rows())
    assert v.state == "clean"
    assert set(v.considered) == {
        "missing-content-type-options",
        "missing-frame-protection",
        "missing-hsts",
    }, "a clean answer that names nothing retires nothing, so a fixed header stays live forever"


def test_an_inconclusive_verdict_considers_nothing():
    """S10: never `clean` when the check could not run, and never with
    `considered` populated either -- a check that could not read the
    evidence has concluded nothing, and retiring on that basis would close a
    finding on missing data."""
    c = security_headers.SecurityHeaders()
    v = c.on_surface(ctx_for(), None, rows())      # d1 absent from the store
    assert v.state == "inconclusive"
    assert v.considered == ()
```
The cookie check's own case is not beside those two in the file -- it sits with the rest of `cookie_flags`' tests -- so it is a second excerpt rather than a gap in the first:

```python
# tests/test_checks_passive.py -- Task 3: a cookie is considered even when it is fine
def test_cookie_flags_considers_every_cookie_the_surface_set():
    """Per-cookie issue types: exactly why `considered` is run-time and not a
    class-level declaration. Both cookies are considered even though only
    one of them is missing anything -- a check that examined a cookie and
    found it fine still examined it."""
    c = cookie_flags.CookieFlags()
    blob = resp(b"Set-Cookie: a=1; Path=/; Secure; HttpOnly; SameSite=Lax",
                b"Set-Cookie: b=2; Path=/")
    v = c.on_surface(ctx_for(d1=blob), None, rows())
    assert len(v.considered) == 2
    assert set(v.considered) == {cookie_flags._issue_type("a"),
                                 cookie_flags._issue_type("b")}
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_checks_passive.py -k considered -v`
Expected: FAIL — `considered` is `()` for the first two.

- [ ] **Step 3: Thread `considered` through the shared verdict helper**

In `src/hx/checks/passive/_http.py`, change the signature and the two constructing returns. Leave both `inconclusive` returns exactly as they are:

```python
# src/hx/checks/passive/_http.py -- Task 3: verdict's signature
def verdict(evidence: Evidence, candidates, *,
            considered: tuple[str, ...] = ()) -> base.Verdict:
```

```python
# src/hx/checks/passive/_http.py -- Task 3: the finding return
    if candidates:
        # F5 of the whole-branch review. This used to pass `considered`
        # unconditionally while the `clean` return below required zero gaps,
        # and the asymmetry retires findings: `considered` is what
        # `hx.scan._mark_unobserved` reads, so a surface holding one
        # unreadable exchange and one candidate found elsewhere claimed to
        # have EXAMINED every issue type this check names -- including,
        # exactly, the type whose only evidence was the exchange that could
        # not be read. The finding is still reported (a candidate wins over a
        # gap, above); what it may not do is retire its neighbours on
        # evidence nobody could read.
        return base.Verdict.finding(
            *candidates, considered=() if evidence.gaps else considered)
```

```python
# src/hx/checks/passive/_http.py -- Task 3: the clean return
    return base.Verdict.clean(considered=considered)
```

Add to that docstring:

```
    `considered` NAMES WHAT THE CHECK EXAMINED, and only the two conclusive
    returns carry it. An `inconclusive` verdict deliberately does not: the
    surface's evidence was incomplete, so the check concluded nothing, and
    `hx.scan._mark_unobserved` must not retire a finding on the strength of a
    response it could not read.
```

- [ ] **Step 4: Pass the examined issue types from each check**

`security_headers.py` — it already iterates a table of headers. Collect the issue type for each header it examines and pass the tuple:

```python
        considered = tuple(spec.issue_type_id for spec in _HEADERS)
        return _http.verdict(ev, candidates, considered=considered)
```

`cookie_flags.py` — collect per cookie occurrence, using the same issue-type spelling the candidate uses, so the two match exactly:

```python
        considered = tuple(_issue_type(name) for name in seen_cookie_names)
        return _http.verdict(ev, candidates, considered=considered)
```

Extract the issue-type construction into a module-level `_issue_type(name)` if it is currently inline, so the candidate and the `considered` entry cannot drift apart. **They must be byte-identical strings** — a mismatch means the finding is never retired and nothing fails.

`secret_in_response.py` and `stack_trace.py` — pass the issue types each scans for, by the same rule.

- [ ] **Step 5: Run the suite**

Run: `.venv/bin/pytest -q`
Expected: the baseline you recorded at the start of this task, plus the tests you added.
Report the line you actually saw. (When this plan was written the arithmetic here would have been `941`; treat that as stale unless it matches what you measured.)

- [ ] **Step 6: Prove the strings match**

Add one test that would catch the silent drift Step 4 warns about:

```python
# tests/test_checks_passive.py -- Task 3: a candidate's issue type is one the check considered
def test_a_cookie_flag_candidates_issue_type_is_one_it_considered():
    """The silent-drift hazard: a candidate whose issue type is not in
    `considered` can never be retired, and nothing else in the suite would
    notice."""
    c = cookie_flags.CookieFlags()
    blob = resp(b"Set-Cookie: session=abc; Path=/")
    v = c.on_surface(ctx_for(d1=blob), None, rows())
    assert v.state == "finding"
    for candidate in v.candidates:
        assert candidate.issue_type_id in v.considered
```

- [ ] **Step 7: Commit**

```bash
git add src/hx/checks/passive tests/test_checks_passive.py
git commit -m "feat(checks): the passive corpus names what it examined"
```

---

## Task 4: bare-LF responses are parsed, not silently emptied

**Files:**
- Modify: `src/hx/checks/passive/_http.py` (`bodies`, `responses`, `header_names`, `header_values`)
- Test: `tests/test_checks_http.py`

**Interfaces:**
- Consumes: nothing.
- Produces: no signature change. `bodies`, `responses`, `header_names` and `header_values` accept `\n` line endings as well as `\r\n`.

**Why this is worse than "mis-parsed headers".** `bodies()` and `responses()` split head from body with `raw.partition(b"\r\n\r\n")`. A response using bare-LF endings contains no `\r\n\r\n`, so `partition` matches nothing and returns `(raw, b"", b"")`. Therefore:

- `bodies()` returns **empty bytes** for every exchange — `secret_in_response` and `stack_trace` search nothing and answer `clean`;
- `responses()` returns the **whole response** as the head — `header_values` splits on `\r\n`, finds one enormous line, and reports no headers at all, so `security_headers` claims every header is missing (a false positive) while `cookie_flags` sees no cookies (a false negative).

All four are wrong, in both directions, and the tool reports clean because it failed to read. RFC 9112 §2.2 requires a recipient to accept a bare LF as a line terminator.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_checks_http.py -- Task 5: the bare-LF corpus and the ordinary path it must not disturb
_LF_RESPONSE = (b"HTTP/1.1 200 OK\n"
                b"Content-Type: text/html\n"
                b"Set-Cookie: session=1\n"
                b"\n"
                b"<html>AKIAIOSFODNN7EXAMPLE</html>")

# The ordinary path this fix must leave alone.
_CRLF_RESPONSE = (b"HTTP/1.1 200 OK\r\n"
                  b"Content-Type: text/html\r\n"
                  b"\r\n"
                  b"<html>ok</html>")


def test_a_bare_lf_response_still_yields_its_body():
    ev = _http.bodies(ctx_for(d1=_LF_RESPONSE), rows())
    assert b"AKIAIOSFODNN7EXAMPLE" in ev.entries[0][1], (
        "the body came back empty, so every body-searching check answers "
        "clean on this server -- a false negative in an assessment")


def test_a_bare_lf_response_still_yields_its_headers():
    ev = _http.responses(ctx_for(d1=_LF_RESPONSE), rows())
    head = ev.entries[0][1]
    assert _http.header_values(head, "content-type") == ["text/html"]
    assert _http.header_values(head, "set-cookie") == ["session=1"]
    assert _http.header_names(head) == ["Content-Type", "Set-Cookie"]


def test_a_crlf_response_is_unchanged():
    """The separating case: the fix must not alter the ordinary path."""
    ev = _http.responses(ctx_for(d1=_CRLF_RESPONSE), rows())
    assert _http.header_values(ev.entries[0][1], "content-type") == ["text/html"]


def test_a_crlf_response_body_is_unchanged():
    """The separating case for `bodies()`: an ordinary CRLF body must come
    back exactly as before, not merely "non-empty"."""
    ev = _http.bodies(ctx_for(d1=_CRLF_RESPONSE), rows())
    assert ev.entries[0][1] == b"<html>ok</html>"


def test_a_lone_cr_inside_a_header_value_does_not_split_it():
    """Guard against over-splitting: normalising must not invent header
    boundaries the wire did not carry. A bare CR is data, not a terminator
    -- RFC 9112 only recognises CRLF and a bare LF as ending a line."""
    head = b"HTTP/1.1 200 OK\r\nX-Note: a\rb\r\n"
    assert _http.header_values(head, "x-note") == ["a\rb"]
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_checks_http.py -k "bare_lf or lone_cr" -v`
Expected: the body test FAILS on an empty body; the header test FAILS with `[]`.

- [ ] **Step 3: Split on the terminator that is actually present**

Add to `_http.py`:

```python
# src/hx/checks/passive/_http.py -- Task 5: the split, and the header lines it feeds
def _split_head_body(raw: bytes) -> tuple[bytes, bytes]:
    """Head and body, accepting either line terminator.

    RFC 9112 s2.2 requires a recipient to accept a bare LF as a line
    terminator. `partition(b"\\r\\n\\r\\n")` on a bare-LF response matches
    nothing and returns `(raw, b"", b"")`, which hands every body-searching
    check an EMPTY body and every header-reading check the whole response as
    one unsplit head. The tool then answers `clean` because it failed to
    read, which is the one direction an assessment must never be wrong in.

    Whichever terminator appears FIRST is the real one, so a body that
    happens to contain `\\r\\n\\r\\n` cannot pull the boundary backwards past
    a head that actually ended with a bare `\\n\\n`.
    """
    crlf = raw.find(b"\r\n\r\n")
    lf = raw.find(b"\n\n")
    if crlf == -1 and lf == -1:
        return raw, b""
    if crlf != -1 and (lf == -1 or crlf <= lf):
        return raw[:crlf], raw[crlf + 4:]
    return raw[:lf], raw[lf + 2:]


def _header_lines(head: bytes) -> list[bytes]:
    """Header lines, minus the status line, for either terminator.

    Splits on LF and strips at most one trailing CR per line, rather than
    also splitting on a bare CR: a lone CR inside a header value is data, and
    splitting on it would invent a header boundary the wire did not carry.
    """
    return [line[:-1] if line.endswith(b"\r") else line
            for line in head.split(b"\n")[1:]]
```

Rewrite the four consumers to use them:

```python
# src/hx/checks/passive/_http.py -- Task 5: the two evidence readers
def bodies(ctx, exchanges) -> Evidence:
    """`(row, body_bytes)` per readable exchange, plus what could not be read."""
    got = _fetch(ctx, exchanges)
    return Evidence(
        tuple((row, _split_head_body(raw)[1]) for row, raw in got.entries),
        got.gaps)


def responses(ctx, exchanges) -> Evidence:
    """`(row, head_bytes)` per readable exchange, plus what could not be read."""
    got = _fetch(ctx, exchanges)
    return Evidence(
        tuple((row, _split_head_body(raw)[0]) for row, raw in got.entries),
        got.gaps)

```
`verdict()` and `_detail()` sit between those and the header readers in the file, so the other two consumers are a second excerpt:

```python
# src/hx/checks/passive/_http.py -- Task 5: the two header readers
def header_names(head: bytes) -> list[str]:
    return [line.partition(b":")[0].decode("latin-1").strip()
            for line in _header_lines(head) if b":" in line]


def header_values(head: bytes, name: str) -> list[str]:
    """Every value for one header name, ASCII-case-insensitively.

    A list, not a value: `Set-Cookie` legitimately repeats, and a parser that
    returned the first would check one cookie of five and report the surface
    clean.
    """
    want = name.lower()
    out = []
    for line in _header_lines(head):
        key, sep, value = line.partition(b":")
        if sep and key.decode("latin-1").strip().lower() == want:
            out.append(value.decode("latin-1").strip())
    return out
```

- [ ] **Step 4: Run the suite**

Run: `.venv/bin/pytest -q`
Expected: the baseline you recorded at the start of this task, plus the tests you added.
Report the line you actually saw. (When this plan was written the arithmetic here would have been `945`; treat that as stale unless it matches what you measured.)

- [ ] **Step 5: Commit**

```bash
git add src/hx/checks/passive/_http.py tests/test_checks_http.py
git commit -m "fix(checks): a bare-LF response is parsed, not read as empty"
```

---

## Task 5: the send seam

**Files:**
- Create: `src/hx/checks/probe.py`
- Test: `tests/test_probe.py`

**Interfaces:**
- Consumes: `hx.bridge.server`'s client, whose `send(req, body, timeout=30.0, *, enforce_locally=True) -> dict` returns the result header plus redacted response bytes under `codec.BODY_KEY`.
- Produces:
  - `ProbeRefused(Exception)` with `.reason: str`
  - `ProbeResponse(status: int | None, head: bytes, body: bytes, outcome: str)`
  - `ProbeSender(bridge, *, scheme, host, port, path)` with `.get(path, *, headers=None, timeout=30.0) -> ProbeResponse`, `.path: str` and `.sent: int`. The keyword was `path_template` as this task was first written and is the surface's CONCRETE address now — F1 of the whole-branch review: five checks built their request line out of the template, so on a templated surface every probe went to a URL that cannot exist and its 404 was recorded as `clean`.

**The two design rules, and why.** The sender **raises** on refusal rather than returning a marker: §10 says a check that cannot run returns `inconclusive`, never `clean`, and a check that receives a refusal as a value can mistake it for an answer. Raising makes the rule structural. And the sender **counts in memory** — the runner writes `check_run.requests_sent` when it closes the row — so `base.CheckContext`'s guarantee that no check ever holds a database connection stays literally true.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_probe.py -- Task 6: the sender's whole contract
def test_a_probe_returns_the_response_and_counts_the_request():
    fb = FakeBridge()
    _ok(fb)
    s = _sender(fb)
    r = s.get("/a?q=1")
    assert r.status == 200 and r.body == b"hi"
    assert probe._http.header_values(r.head, "x-a") == ["b"]
    assert s.sent == 1


@pytest.mark.parametrize("cls", [
    "budget_exhausted", "halted", "rate_limited", "scope_denied",
    "method_denied", "dangerous_denied", "transport_error", "timeout",
    "bridge_lost", "not_configured",
])
def test_every_refusal_raises_and_names_itself(cls):
    fb = FakeBridge()
    fb.refuse(cls)
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused) as exc:
        s.get("/a")
    assert exc.value.reason == cls


# --- what `requests_sent` counts -------------------------------------------
#
# ISSUANCES, NOT ATTEMPTS. This pair replaces `test_a_refused_attempt_is_
# still_counted`, which encoded the opposite rule ("the budget was spent
# whether or not an answer came back") and was wrong for every gate class:
# `hx.policy.Limiter.check` increments `issued` on the ALLOW path only and
# says so in its own words -- "Refusals are not issuances and do not appear
# here" -- so a request the gate refused never left the JVM and the target
# never saw it. `check_run.requests_sent` is this build's record of hx's own
# traffic -- NOT something a report renders, which is what this comment used
# to say and `hx.report._insertion_coverage` contradicts in as many words
# (finding 7 of the final review) -- and it is also what a bounded retry
# would otherwise double-count.


@pytest.mark.parametrize("cls", [
    "scope_denied", "method_denied", "dangerous_denied", "rate_limited",
    "budget_exhausted", "halted", "not_configured",
])
def test_a_refusal_the_gate_decided_before_issuing_counts_nothing(cls):
    """Each of the seven is decided before a request is issued -- the first
    five by `Limiter`/`Policy` inside the JVM, the last two by
    `BridgeServer.send` before a frame is even written -- so none of them is
    traffic, and a report that counted them would overstate what hx put on a
    client's system."""
    fb = FakeBridge()
    fb.refuse(cls)
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused):
        s.get("/a")
    assert s.sent == 0


@pytest.mark.parametrize("cls", [
    "transport_error", "timeout", "bridge_lost", "a_class_from_a_later_build",
])
def test_a_refusal_that_may_already_have_left_counts_as_a_request(cls):
    """The default direction, and it is deliberately the counting one. These
    three classes describe a request that reached the wire and then failed,
    and the fourth is a class this build has never seen: a rule written as an
    enumeration of what COUNTS would file every future class as free traffic,
    which is the one direction this number must not lean."""
    fb = FakeBridge()
    fb.refuse(cls)
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused):
        s.get("/a")
    assert s.sent == 1


def test_a_response_that_did_not_come_back_whole_is_also_refused():
    # A `result` frame is not automatically a whole answer: Sender.java sets
    # outcome="status_unreadable" when the peer's status line could not be
    # read, and _http.py treats that the same way -- a gap, not proof of
    # absence. get() applies the same rule at the wire rather than handing a
    # check a response it could misread as clean. It is still a request that
    # was issued -- the peer answered it -- so it is still counted.
    fb = FakeBridge()
    fb.reply({"status": 599, "outcome": "status_unreadable"}, b"")
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused) as exc:
        s.get("/a")
    assert exc.value.reason == "status_unreadable"
    assert s.sent == 1


# --- pacing: the one refusal class that is a request to wait ---------------


def test_a_rate_limited_probe_waits_the_hint_out_and_then_succeeds():
    """The half of the `retry_after_us` contract that was never written.

    `Limiter` refuses an over-rate request and says exactly when the window
    frees; `tests/integration/test_send_path.py::test_the_rate_limit_trips_
    and_its_retry_hint_is_true` states the contract as "the agent obeys
    `retry_after_us`". Nothing obeyed it until the probe pass became the
    first thing in the product to issue requests in a loop, and an unpaced
    loop at a production rate reports `inconclusive` for every probe after
    the `rate_rps`'th.

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? A sender that raised on the
    first refusal never makes the second call, so `fb.calls` is 1 and the
    `get` raises instead of returning.
    """
    fb = FakeBridge()
    _ok(fb)
    fb.refuse("rate_limited", "rate limit 3/s", retry_after_us=1000, times=1)
    s = _sender(fb)

    started = time.monotonic()
    r = s.get("/a")

    assert r.status == 200
    assert fb.calls == 2
    assert time.monotonic() - started >= 1000 / 1_000_000
    # ONE issuance, not two. The refused attempt never left the JVM, so a
    # sender that counted attempts would report this probe as twice the
    # traffic it actually was -- which is why the counting rule above and
    # this retry are one change and not two.
    assert s.sent == 1


def test_the_wait_is_bounded_and_ends_in_a_refusal(monkeypatch):
    """A limiter that never frees must not spin. Three attempts, two waits,
    and then the refusal the check would have got anyway -- with the
    requests still counted at zero, because none of them was issued."""
    waits: list[float] = []
    monkeypatch.setattr(probe.time, "sleep", waits.append)
    fb = FakeBridge()
    fb.refuse("rate_limited", "rate limit 3/s", retry_after_us=1000)
    s = _sender(fb)

    with pytest.raises(probe.ProbeRefused) as exc:
        s.get("/a")

    assert exc.value.reason == "rate_limited"
    assert probe._RATE_LIMIT_ATTEMPTS == 3
    assert fb.calls == probe._RATE_LIMIT_ATTEMPTS
    assert len(waits) == probe._RATE_LIMIT_ATTEMPTS - 1
    assert s.sent == 0


def test_an_over_large_hint_is_clamped_rather_than_obeyed(monkeypatch):
    """The hint crosses a trust boundary. `Limiter` computes it as
    `WINDOW_US - elapsed` with `0 < elapsed < WINDOW_US`, so it can never
    legitimately exceed one second -- and a peer that answered with ten
    minutes would otherwise stall a scan for ten minutes per probe. The
    clamp costs nothing a real limiter would ever ask for."""
    waits: list[float] = []
    monkeypatch.setattr(probe.time, "sleep", waits.append)
    fb = FakeBridge()
    fb.refuse("rate_limited", "", retry_after_us=600_000_000)  # ten minutes
    s = _sender(fb)

    with pytest.raises(probe.ProbeRefused):
        s.get("/a")

    ceiling = probe._RETRY_CEILING_S + probe._RETRY_SLACK_S
    assert waits == [ceiling, ceiling]


@pytest.mark.parametrize("hint", [None, 0, -1, "soon"])
def test_a_rate_limit_with_no_usable_hint_is_terminal(hint):
    """The direction that spins. `Limiter` always sends a positive hint when
    it refuses for rate, so a missing, zero, negative or non-numeric one
    means something else answered -- and inventing a wait for a refusal that
    did not ask for one is how a scan loops against a peer that will never
    let it through."""
    fb = FakeBridge()
    fb.refuse("rate_limited", "", retry_after_us=hint)
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused):
        s.get("/a")
    assert fb.calls == 1


@pytest.mark.parametrize("cls", [
    "budget_exhausted", "scope_denied", "method_denied", "dangerous_denied",
    "halted", "not_configured", "transport_error", "timeout", "bridge_lost",
    "a_class_from_a_later_build",
])
def test_no_other_class_is_retried_even_when_it_carries_a_hint(cls):
    """`rate_limited` is an ALLOWLIST of one, not a denylist. A budget that
    is spent stays spent, scope and method are deterministic policy, `halted`
    and `not_configured` are session state, and a transport failure may
    already have reached the target -- replaying that one blindly is the
    thing S6 forbids. A class this build has never seen is terminal too,
    which is what an allowlist buys."""
    fb = FakeBridge()
    fb.refuse(cls, "", retry_after_us=1000)
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused):
        s.get("/a")
    assert fb.calls == 1


# --- the client-facing string ----------------------------------------------


def test_the_refusal_names_its_class_once():
    """OBSERVED, against a real Burp: `probe refused: rate_limited:
    rate_limited: rate limit 3/s: ...`. `BridgeError`'s message already opens
    with the class, `ProbeRefused` put the reason in front of it again, and
    `hx.scan.run` prefixes the whole thing a third time on its way into
    `check_run.reason` -- which is what a client reads in the report's
    coverage rows."""
    fb = FakeBridge()
    fb.refuse("rate_limited", "rate limit 3/s: 3 requests issued in the last second")
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused) as exc:
        s.get("/a")
    assert str(exc.value) == (
        "rate_limited: rate limit 3/s: 3 requests issued in the last second")
    assert str(exc.value).count("rate_limited") == 1
    assert exc.value.detail == "rate limit 3/s: 3 requests issued in the last second"


def test_a_refusal_carrying_no_detail_is_just_its_class():
    """`BridgeServer.send` raises a bare `BridgeError("halted",
    error_class="halted")` for a local halt, so stripping the class prefix
    leaves the class itself -- which must become an empty detail rather than
    `halted: halted`."""
    fb = FakeBridge()
    fb.refuse("halted")
    s = _sender(fb)
    with pytest.raises(probe.ProbeRefused) as exc:
        s.get("/a")
    assert str(exc.value) == "halted"
    assert exc.value.detail == ""


def test_the_sender_only_ever_issues_GET():
    # S7: the method allowlist is GET/HEAD/OPTIONS and Config carries no
    # method key. A sender that could emit POST would be refused by the
    # extension anyway -- this pins that hx does not even try.
    fb = FakeBridge()
    fb.reply({"status": 200, "outcome": "ok"}, b"HTTP/1.1 200 OK\r\n\r\n")
    s = _sender(fb)
    s.get("/a")
    assert fb.last_body.startswith(b"GET ")


def test_the_sender_cannot_be_pointed_at_another_host():
    # A check receives a sender already bound to its surface. Redirect
    # following and cross-host probing are both out of reach by construction,
    # not by convention.
    fb = FakeBridge()
    s = _sender(fb)
    assert not hasattr(s, "host")
    with pytest.raises(ValueError):
        s.get("https://evil.test/a")
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_probe.py -v`
Expected: FAIL — `No module named 'hx.checks.probe'`.

- [ ] **Step 3: Write the seam**

```python
# src/hx/checks/probe.py
"""The one route from a check to the wire.

A check does not own a socket and cannot construct one. It is handed a
`ProbeSender` already bound to its surface, and every request goes through
`hx.bridge.server.BridgeServer.send` into the extension -- so S4 holds
unchanged: every byte that leaves this machine still crosses one of two
points inside the JVM, and this module adds neither.

THREE RULES, ALL STRUCTURAL RATHER THAN DOCUMENTED.

A REFUSAL RAISES. S10 says a check that cannot run returns `inconclusive`,
never `clean`. A sender that RETURNED a refusal would leave a check free to
read it as a response and carry on to a clean answer; `budget_exhausted`
would then render as `tested, clean`, which is exactly the confusion S12
calls worse than no report. Raising takes the choice away.

THE SENDER HOLDS NO DATABASE CONNECTION. It counts in memory and the runner
writes `check_run.requests_sent` when it closes the row, so
`hx.checks.base.CheckContext`'s guarantee -- "a check that can write is a
check that can write the wrong thing" -- stays literally true of everything a
check can reach.

A PROBE GOES TO A CONCRETE PATH, NEVER TO A TEMPLATE. A surface's identity
is `path_template` -- `hx.surface` normalises `/user/12345/profile` into
`/user/{id}/profile`, and S5 says that merge is the point -- but a template
is an identity and not an address: `GET /user/{id}/profile` reaches a URL
that cannot exist, and the 404 that comes back carries none of the headers,
reflections or signatures a check is looking for. Every active check in this
build answered `clean` from exactly that request, with `considered`
populated, so `hx.scan._mark_unobserved` retired live findings on the
strength of a probe that tested nothing. The sender is therefore bound at
construction to the CONCRETE path of the surface's exemplar request
(`hx.insertion.request_path`, resolved by `hx.scan.run`, which skips the
check outright when it cannot be read), exposes it as `path`, and `get()`
REFUSES a path still carrying a placeholder. That refusal is a `ValueError`
and not a `ProbeRefused`, like the origin-form guard beside it and for the
same reason: nothing on the wire said no, a caller made a mistake, and a
`ProbeRefused` would land it in `check_run` as an ordinary `inconclusive`
row indistinguishable from a rate limit. A future check cannot reintroduce
the defect by reading `surface[5]`, because the seam will not send it.

`BridgeServer.send` DOES NOT RETURN A REFUSAL AS A DICT. It raises
`hx.bridge.server.BridgeError` -- with the wire's class on `.error_class` --
for every one of them: this side's own local enforcement (`halted`,
`not_configured`), a timed-out or disconnected peer (`timeout`,
`bridge_lost`), and every `error` frame the extension answers with
(`scope_denied`, `method_denied`, `dangerous_denied`, `rate_limited`,
`budget_exhausted`, `transport_error`, ...). `get()` below is what turns that
raised `BridgeError` into a raised `ProbeRefused`, so rule one above holds
against the bridge as it actually behaves, not against a dict shape it never
produces.

A SUCCESSFUL SEND CAN STILL NOT BE A WHOLE ANSWER. The result frame carries
its own `outcome` (`ok`, or `status_unreadable` when the peer's status line
could not be read -- see `Sender.java`), the same field
`hx.checks.passive._http` reads off a stored `exchange` row and treats as a
gap rather than proof of absence. `get()` applies the identical rule at the
wire: only `outcome == "ok"` is handed back as a `ProbeResponse`, and
anything else raises `ProbeRefused` too, for the same reason -- a check must
not be able to read an incomplete response as a clean one.

ONE REFUSAL CLASS IS A REQUEST TO WAIT, AND THIS IS THE SEAM THAT OBEYS IT.
`hx.policy.Limiter` REFUSES an over-rate request rather than queueing it, and
puts the exact moment the window frees on the refusal --
`Decision.rateLimited(WINDOW_US - elapsed, ...)`, which `BridgeServer.send`
carries out to Python on `BridgeError.retry_after_us`. That hint is computed
exactly, plumbed through four layers and pinned end to end
(`tests/integration/test_send_path.py::test_the_rate_limit_trips_and_its_
retry_hint_is_true`, whose own docstring states the contract: "the agent
obeys `retry_after_us`"). Nothing on this side consumed it until the probe
pass became the first thing in the product to issue requests in a loop, and
an unpaced probe pass at a production rate is not a slow scan, it is a scan
that reports `inconclusive` for every probe after the `rate_rps`'th and finds
almost nothing. MEASURED against a real Burp at the integration rig's 3/s: of
the sixteen probes one scan of five surfaces issues, three were answered and
thirteen were refused.

`rate_limited` ONLY, AS AN ALLOWLIST AND NEVER AS A DENYLIST. Every other
class is terminal, and a new class arriving from a future extension is
terminal by default rather than accidentally retried: `scope_denied`,
`method_denied` and `dangerous_denied` are deterministic policy and answer
the same way for ever; `budget_exhausted` is monotonic by construction
(`Limiter`: "a budget that is spent stays spent", with no way to refill it);
`halted` and `not_configured` are session state that a wait does not change;
and `transport_error`, `timeout` and `bridge_lost` may have already reached
the target, so replaying them blindly is the one thing a safe sender may not
do.

THE WAIT IS HERE AND NOT IN `BridgeServer`. That module's "NOTHING IN THIS
FILE RETRIES" stays literally true, and it should: S6's objection is that a
replayed STATE-CHANGING request is worse than a failed one, and only a caller
knows whether its request was one. This sender is a caller that does know.
`_request_bytes` can build nothing but a GET, and `Limiter.check` increments
`issued` on the ALLOW path only -- "Refusals are not issuances and do not
appear here" -- so a request refused for rate never left the JVM and a
bounded retry cannot double-spend `limit.max_requests`. The published
decision order is `not_configured, halted, scope, method, dangerous, rate,
budget`, so a `rate_limited` answer also means scope, method and dangerous
ALREADY PASSED: waiting cannot turn a denial into an allow.

THE HINT CROSSES A TRUST BOUNDARY, SO IT IS BOUNDED IN BOTH DIRECTIONS. A
missing or non-positive hint is terminal -- inventing a wait for a refusal
that did not ask for one is how a scan spins -- and an over-large one is
CLAMPED to `_RETRY_CEILING_S` rather than obeyed, so a peer cannot stall a
scan by answering with a huge number. The clamp costs nothing real:
`retryAfterUs` is `WINDOW_US - elapsed` with `0 < elapsed < WINDOW_US`, so a
`Limiter` cannot legitimately ask for more than one second. Attempts are
bounded at `_RATE_LIMIT_ATTEMPTS`, which puts a ceiling of roughly two
seconds on what any one probe can add. `hx.scan.run` does NOT bound the run
by `max_seconds` -- it consults its deadline only at the top of its surface
loop (`run`'s `if deadline is not None`), so `max_seconds` bounds when the
next surface starts,
not when the run ends: once a surface is in flight every check on it runs
to completion, and this retry can add its ceiling to each probe issued
there. That overshoot is accepted, not fixed: it is bounded (one surface's
probes, worst case tens of seconds), the safety envelope is
`limit.max_requests` and the rate limit rather than `max_seconds`, and
`_skip_rest(..., "budget", ...)` already records a skipped row for every
check a deadline miss does cut off. No deadline is threaded through here.

THE COUNT IS OF ISSUANCES, NOT ATTEMPTS. `check_run.requests_sent` is the
column this build keeps its record of hx's OWN traffic in, and a record of
what hx put on a client's system has to be true of the requests that were
actually made.

WHAT THAT DOES NOT REST ON, because an earlier version of this sentence did:
`requests_sent` does not reach a client's report. Nothing in `hx.report`
renders it -- `_insertion_coverage` says in as many words that it is deferred
-- so the ground is the column and not a page, and the two comments said
opposite things until finding 7 of the final review caught it. What does turn
on the column: `hx.scan._close_row` writes it for every row, so it is where
an operator asking "what did hx send against this surface" has to look --
there is nowhere else -- and a report section that starts rendering it
inherits the rule that is here rather than getting to choose one. The rule
below is right on those grounds; it was never right on the one it used to
give.

`Limiter` decides `scope_denied`, `method_denied`, `dangerous_denied`,
`rate_limited` and `budget_exhausted`
BEFORE issuing and never increments `issued` for them; `halted` /
`not_configured` are refused on this side before a frame is written at all;
and `unmanaged_credential` is decided by `Sender.decide()` ahead of both the
Gate and `http.send`, placed there in that method's own words so that
`Limits.check()` does not "spend a rate token and a budget slot on a request
that is about to be refused". `unknown_identity` and `identity_origin` are
that same method's last two refusals and sit on the OTHER side of the Gate --
`Limiter.check` has already incremented `issued` by the time either is
decided, so those two DO spend a rate token and a budget slot in the JVM --
but both `return error(...)` above `compose()` and `http.send`, so the target
saw nothing and this set is about what hx put on a client's system. So none
of the ten is a request the target
saw, and counting them would overstate the traffic AND make every retry above
double-count. Everything else counts, by default and including a class this
build has never seen: `transport_error`, `timeout` and `bridge_lost` may
already have reached the target, and a `status_unreadable` outcome certainly
did. Overstating traffic is the safe direction; understating what hx put on a
client's system is not.

A POINT THE SEND PATH STRUCTURALLY REFUSES IS NOT PROBED AT ALL. That same
`unmanaged_credential` refusal covers any request carrying a `Cookie`,
`Authorization` or `Proxy-Authorization` header the extension did not itself
inject (`Redactor.CREDENTIAL_HEADERS`; S7's "refused AND NEVER PERSISTED" is
why the rule exists). A `cookie` insertion point can only be filled in by
sending a `Cookie` header, and a `header` point named after one of the three
by sending that name -- so a probe there is refused before the Gate, every
time, whatever it carries. F2 of the whole-branch review: `insertion.derive`
returns points sorted by `(kind, name)`, so `cookie` sorted FIRST, and
`hx.active.reflected-input` spent its first probe on a guaranteed refusal on
every cookie-bearing engagement. `unprobeable()` below names those points and
`hx.scan.run` drops them before a check is handed its own; the three header
names are spelt HERE, once, in the module that already models what the send
path will and will not carry, rather than in each check that declares a
`header` or `cookie` kind. What the CLIENT is told about them is
`hx.report._limits`' business: a Limits bullet says they were not probed and
renders the three names off `CREDENTIAL_HEADERS` below. The Coverage table
carries the per-point sentences too since fix round 4 (see `unprobeable`), but
only where a whole check was skipped for want of a probeable point; the bullet
is what makes the disclosure for the ordinary case, where other points on the
same surface were probed and the check ran. It deliberately does
NOT cross-reference the report's "Insertion points" table -- N4 of the scoped
re-review, because an earlier version of this paragraph said the opposite.
That table counts points by kind and states in as many words that this build
records no per-insertion probe attribution, so it cannot say which points
were probed; and it renders only where a point could be derived at all
(`report._insertion_coverage` returns nothing when no exemplar request blob
could be read), so a bullet naming it could name a section that is not on
the page.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from hx import insertion as insertion_mod
from hx.bridge.server import BridgeError, BridgeServer
from hx.checks.passive import _http

# ATTEMPTS, not retries: 3 is one issue and at most two waits, so the worst
# case a single probe can add to a scan is two clamped waits (~2 s).
_RATE_LIMIT_ATTEMPTS = 3

# The most a `Limiter` can legitimately ask for is one window, and the window
# is one second (`Limiter.WINDOW_US`). A larger hint is a peer that is wrong
# or hostile, and either way it does not get to decide how long hx waits.
_RETRY_CEILING_S = 1.0

# The same slack `tests/integration/test_send_path.py` already waits with:
# the hint is exact about when the window frees, and two clocks that are
# exactly equal are two clocks that race.
_RETRY_SLACK_S = 0.02

# The refusal classes the gate decides BEFORE issuing, so none of them is a
# request the target saw. Named as an EXCLUSION set on purpose -- see the
# module docstring's last paragraph: anything not listed here counts.
_NOT_ISSUED = frozenset({
    "scope_denied", "method_denied", "dangerous_denied", "rate_limited",
    "budget_exhausted", "halted", "not_configured",
    # F8 of the whole-branch review. `Sender.decide()` refuses this one BEFORE
    # the Gate and before `http.send` -- deliberately, so that a request about
    # to be refused does not spend a rate token and a budget slot -- so it is
    # in exactly the position of the seven above it and belongs in the same
    # set. `bad_frame` and the pre-send `timeout` at `Sender.java:220` are
    # there too and are NOT listed: nothing reachable from this sender can
    # produce them, and a name here that no input can exercise is a claim no
    # test separates from its absence.
    "unmanaged_credential",
    # The identity pair, and they are here on the same ground and NOT on the
    # same mechanism -- see the module docstring. `Sender.decide()` answers
    # both after `policy.checkGate` rather than before it, so each has already
    # cost a rate token and a budget slot inside the JVM; what neither has
    # done is reach the target, because both `return error(...)` above
    # `compose()` and `http.send`. The set is about the traffic hx put on a
    # client's system, so both belong in it. Reachable from this sender the
    # moment one is bound to an identity: `unknown_identity` is what every
    # probe draws if registration never happened, and `identity_origin` is
    # what a probe at a host outside the identity's origins draws.
    "unknown_identity", "identity_origin",
})

# The header names `Sender.decide()` will not carry from a check, matching
# `Redactor.CREDENTIAL_HEADERS` byte for byte and lower-cased for the same
# ASCII-insensitive comparison `Redactor.asciiEqualsIgnoreCase` makes. Kept as
# data rather than spelt into `unprobeable`'s body so that the one place this
# build states the rule is greppable from both sides of the seam --
# `hx.report._limits` renders these names at the client.
CREDENTIAL_HEADERS = frozenset({
    "authorization", "cookie", "proxy-authorization",
})


def unprobeable(insertion) -> str | None:
    """Why the send path refuses every probe at this point, or None.

    See the module docstring's last paragraph. The answer is a property of
    the POINT, not of the payload or of the check, which is what makes it
    decidable before anything is sent: `hx.scan.run` drops these points from
    what a check is handed, so no budget and no bridge round trip is spent on
    an attempt whose only possible outcome is `unmanaged_credential`.

    A `cookie` point of ANY name is refused, because the only way to fill one
    in is a `Cookie` header. A `header` point is refused only when its own
    name is one of the three -- an ordinary `Accept` or `User-Agent` header is
    probed as before. `hx.insertion.derive` cannot currently mint a `header`
    point called `Cookie` (its cookie branch `continue`s first), and the name
    is matched here anyway: this function answers for the send path's rule,
    not for one derivation's current output.

    A COVERAGE ROW SHOWS THE SENTENCE, which is why it is short. `hx.scan.run`
    is the only caller: it drops every point this answers for, and where that
    leaves a check nothing at all it appends these sentences -- through
    `_http._detail`, the formatter a gap from `_probe_util` goes through, so
    the list is capped and counted the same way -- to the
    `no_probeable_insertion_point` skip reason, which `hx.report._coverage`
    renders. An operator reading that row sees WHICH points were refused and
    under which of the two rules, rather than only that some were.

    THIS DOCSTRING HAS BEEN WRONG IN BOTH DIRECTIONS, which is worth the two
    lines. It claimed exactly the paragraph above while `scan.run` tested the
    result for `None` and threw the string away (N4 of the scoped re-review),
    was corrected to say nothing rendered it, and then the code caught up with
    the original claim (Concern 5 of fix round 3). What never changed is why
    this is a `str` and not a `True`: two rules refuse a point, and a reader
    of a skip cannot tell them apart from a bool.
    """
    if insertion.kind == "cookie":
        return (f"cookie {insertion.name!r}: a cookie is probed by sending a "
                "Cookie header, which the send path refuses")
    if insertion.kind == "header" and insertion.name.lower() in CREDENTIAL_HEADERS:
        return (f"header {insertion.name!r}: the send path refuses a "
                "credential header it did not inject")
    return None


def _placeholder_in(path: str) -> str | None:
    """The first template placeholder segment in `path`, or None.

    `hx.insertion.is_placeholder` decides the shape, because that module is
    already the one that turns a placeholder into an insertion point and two
    spellings of the test could disagree. The query string is not examined:
    every check percent-encodes what it puts there (`quote(safe="")` escapes
    `{` to `%7B`), so a brace can only reach the request line's PATH.

    A target that genuinely serves a `{...}` path segment is refused here
    too, which is a false positive with no better answer available: the
    segment is indistinguishable from an unsubstituted template, and the
    refusal is an `error` row -- visible, and retiring nothing -- while
    guessing the other way is F1 again. `hx.surface._kept_segment`
    percent-encodes such a segment when it templates it, so that surface's
    own `path_template` does not carry braces either.
    """
    for segment in path.partition("?")[0].split("/"):
        if insertion_mod.is_placeholder(segment):
            return segment
    return None


class ProbeRefused(Exception):
    """The request did not produce an answer. `reason` is the wire's class."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class ProbeResponse:
    status: int | None
    head: bytes
    body: bytes
    outcome: str


def _rate_limit_wait(exc: BridgeError) -> float | None:
    """Seconds to wait out a `rate_limited` refusal, or None if it is terminal.

    None for a hint that is absent, non-numeric or non-positive: `Limiter`
    always sends a positive one when it refuses for rate, so its absence means
    something other than that limiter answered and there is nothing to wait
    for. Waiting anyway -- a default, a backoff -- is what makes a scan spin
    against a peer that will never let it through.
    """
    hint = exc.retry_after_us
    if not isinstance(hint, (int, float)) or isinstance(hint, bool) or hint <= 0:
        return None
    return min(hint / 1_000_000, _RETRY_CEILING_S) + _RETRY_SLACK_S


class ProbeSender:
    """Bound to one surface for the life of one `check_run`, and to at most
    one identity for the life of the run.

    THE IDENTITY IS AN ID AND NEVER A CREDENTIAL. What travels here is the
    name the extension's `IdentityRegistry` holds the credential under; the
    value itself reached the JVM once, through `BridgeServer.
    register_identity`, and is written into the request there -- after every
    gate, so a refused request never has one composed for it. Nothing on this
    side of the bridge can put a credential on the wire, which is what keeps
    S7's redaction claim ("the extension knows exactly which byte ranges it
    injected") true of every request a check causes.

    A CHECK STILL CANNOT SEE ANY OF THIS. It is handed a sender already
    bound, exactly as it is handed one already bound to a surface: S7 puts
    identity below the check layer, and `hx.scan.run` decides.
    """

    def __init__(self, bridge, *, scheme: str, host: str, port: int,
                 path: str, identity_id: str | None = None) -> None:
        self._bridge = bridge
        self._scheme = scheme
        self._host = host
        self._port = port
        self._path = path
        self._identity_id = identity_id
        self._sent = 0
        self._refused: dict[str, int] = {}

    @property
    def sent(self) -> int:
        return self._sent

    @property
    def refused(self) -> dict[str, int]:
        """How many probes ended in a refusal, by the wire's own class.

        F11 of the whole-branch review. `hx.scan.run` builds the run row's
        `stop_reason` from what it can SEE, and what it could see was skips:
        a `budget_exhausted` arrives as a raised `ProbeRefused`, lands the
        `check_run` row `inconclusive`, and left the run itself closing
        `('completed', NULL)` -- byte-identical at the run row to a pass that
        covered every surface. A scan that spent its whole budget at surface
        10 of 500 overstated its own coverage, which is S12's core
        prohibition.

        COUNTED HERE BECAUSE THE RUNNER CANNOT SEE THEM ANY MORE. Since F2,
        a check catches its own refusals per insertion point
        (`_probe_util.send_or_gap`) and answers with a verdict, so the
        runner's `except ProbeRefused` is no longer where most refusals
        arrive. This dict is what crosses that seam. It counts TERMINAL
        refusals only -- a `rate_limited` attempt that was waited out and
        then answered is not one, or a paced scan would report itself
        truncated for having worked.

        A COPY, like `sent` is a number: a caller that could mutate this
        could make the run row say something the pass did not do.
        """
        return dict(self._refused)

    @property
    def path(self) -> str:
        """The concrete path this surface's exemplar request asked for.

        WHAT A CHECK BUILDS ITS PROBE FROM, in place of `surface[5]`. The
        surface row carries the TEMPLATE, which is an identity rather than an
        address -- see the module docstring's third rule -- and this is the
        address the capture that proved this surface exists actually used.
        Read-only: a sender is bound to one surface for the life of one
        `check_run`, and a check that could move it could point it somewhere
        the operator never authorised.
        """
        return self._path

    def get(self, path: str, *, headers: dict[str, str] | None = None,
            timeout: float = 30.0) -> ProbeResponse:
        if not path.startswith("/"):
            raise ValueError(
                f"path must be origin-form and start with '/', got {path!r}; "
                "a sender is bound to one surface and cannot be pointed "
                "somewhere else")
        placeholder = _placeholder_in(path)
        if placeholder is not None:
            # STRUCTURAL, NOT DOCUMENTED. A check that reaches for
            # `surface[5]` -- or substitutes one placeholder of two -- is
            # asking to send a request to an address that cannot exist and
            # then to read the 404 as an answer. The one thing that makes
            # that unrepeatable is a seam that will not carry it.
            raise ValueError(
                f"path still holds the template placeholder {placeholder!r}: "
                f"{path!r}. A surface's `path_template` is its identity, not "
                "an address; build the probe from `sender.path` -- the "
                "exemplar's own concrete path -- and substitute into that")
        raw = self._request_bytes(path, headers or {})
        req = {"target_host": self._host, "target_port": self._port,
               "tls": self._scheme == "https"}
        if self._identity_id is not None:
            # PRESENT ONLY WHEN BOUND. An absent key is "anonymous"; a null
            # would leave the extension deciding what a null means. It reads
            # the field as `header.get("identity_id") instanceof String`
            # (`Sender.decideAndIssue`), so a null happens to be anonymous
            # there today -- and a key this side sends only when it means
            # something cannot be given a second meaning by a later reader.
            req["identity_id"] = self._identity_id
        attempts_left = _RATE_LIMIT_ATTEMPTS
        while True:
            attempts_left -= 1
            try:
                result = self._bridge.send(req, raw, timeout=timeout)
            except BridgeError as exc:
                # BridgeServer.send() never returns a refusal -- it raises
                # this, with the wire's class on .error_class (None only for a
                # malformed call or a peer answering a send with the wrong
                # frame, the second of which HAS already put bytes on the
                # wire). Translating it here is what makes rule one hold in
                # practice.
                cls = exc.error_class or "transport_error"
                if cls not in _NOT_ISSUED:
                    # Counted before the raise and before the retry decision:
                    # this attempt may have reached the target, and a class
                    # this build has never seen counts too.
                    self._sent += 1
                wait = _rate_limit_wait(exc) if cls == "rate_limited" else None
                if wait is not None and attempts_left > 0:
                    time.sleep(wait)
                    continue
                # `BridgeError`'s own message already opens with the class
                # ("rate_limited: rate limit 3/s: ..."), and `ProbeRefused`
                # puts the reason in front of the detail again -- which
                # `hx.scan.run` then prefixes a third time on its way into
                # `check_run.reason` and the report's coverage rows.
                detail = str(exc).removeprefix(f"{cls}: ")
                # AFTER the retry decision, so a `rate_limited` that was
                # waited out and then answered is not recorded as one: this
                # count reaches the run row as a reason the pass was
                # truncated, and a paced scan was not.
                self._refused[cls] = self._refused.get(cls, 0) + 1
                raise ProbeRefused(cls, "" if detail == cls else detail) from exc
            # The send returned a `result` frame, so a request was issued --
            # whatever the frame then says about how much of the answer came
            # back.
            self._sent += 1
            outcome = result.get("outcome", "ok")
            if outcome != "ok":
                self._refused[outcome] = self._refused.get(outcome, 0) + 1
                raise ProbeRefused(
                    outcome, "the response did not come back whole, so nothing "
                             "found in it separates tested from unreachable")
            head, body = _http._split_head_body(
                result.get(BridgeServer.BODY_KEY, b""))
            return ProbeResponse(result.get("status"), head, body, outcome)

    def _request_bytes(self, path: str, headers: dict[str, str]) -> bytes:
        lines = [f"GET {path} HTTP/1.1", f"Host: {self._host}"]
        lines += [f"{k}: {v}" for k, v in headers.items()]
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_probe.py -v`
Expected: all pass.

- [ ] **Step 5: Run the suite**

Run: `.venv/bin/pytest -q`
Expected: the baseline you recorded at the start of this task, plus the tests you added.
Report the line you actually saw. (When this plan was written the arithmetic here would have been `959`; treat that as stale unless it matches what you measured.)

- [ ] **Step 6: Commit**

```bash
git add src/hx/checks/probe.py tests/test_probe.py
git commit -m "feat(checks): the send seam, where a refusal cannot look like an answer"
```

---

## Task 6: the request budget gets a number and a writer

**Files:**
- Modify: `src/hx/config.py`, `src/hx/session.py` (`config_body`), `src/hx/cli.py`
- Test: `tests/test_config.py`, `tests/test_session_configure.py`

**Interfaces:**
- Consumes: `session.config_body(cfg)`, which today returns seven keys and deliberately omits `limit.max_requests`.
- Produces: `Config.max_requests: int = 2000`; `config_body` emits `limit.max_requests`; `hx capture start` and `hx scan` accept `--max-requests`.

**Why this is wiring, not design.** §5 settles the semantics and the implementation follows rather than reinterprets them: the budget is **per run**, taken from the **first** authorisation, **monotonic**, and a later `configure` naming a different rate or budget is **refused**, not applied. `bridge/codec.py`'s `CONFIG_KEYS` already permits `limit.max_requests`; Java's `Limits.arm()` already reads it, falling back to a default `Distress.java` documents as 2000. Only `Config` lacks the field.

**The docstring you must rewrite, because this task makes it false.** `config_body` currently says the key is absent since "nothing this plan starts spends the budget, so bounding it here would be a number with no referent." This plan starts something that spends it. Replace that paragraph with what is true after this task: the key is emitted, the value comes from `Config`, and the default matches Java's so an operator who sets nothing gets the documented behaviour rather than a silent change.

- [ ] **Step 1: Write the failing tests**

Sketch — adapt to `tests/test_config.py`'s existing fixture style rather than transcribing.

```python
def test_max_requests_defaults_to_javas_documented_default():
    # Distress.java documents 2000 as Limits.arm()'s fallback. Matching it
    # means adding the key changes no behaviour for an operator who sets
    # nothing -- the number was always 2000, it was just never said.
    assert config.Config(name="n", client="c", scope_include=["https://a/*"]).max_requests == 2000


def test_max_requests_must_be_a_positive_integer(tmp_path):
    for bad in ("0", "-1", "true", "many"):
        p = _write_config(tmp_path, max_requests=bad)
        with pytest.raises(config.ConfigError):
            config.load(p)


def test_the_budget_reaches_the_authorisation(a_config):
    assert session.config_body(a_config)["limit.max_requests"] == [str(a_config.max_requests)]


def test_the_budget_key_is_one_the_codec_permits(a_config):
    assert set(session.config_body(a_config)) <= codec.CONFIG_KEYS
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_config.py tests/test_session_configure.py -k max_requests -v`
Expected: FAIL — `Config` has no attribute `max_requests`.

- [ ] **Step 3: Add the field**

`Config` gains `max_requests: int = 2000`, loaded through the existing `_positive_int` helper (which already rejects `bool`, because `max_requests: true` must not become `1`), and dumped by `dumps` beside `rate_limit_rps`.

- [ ] **Step 4: Emit the key**

```python
# src/hx/session.py -- Task 7: the budget key in the configure body
        "limit.max_requests": [str(cfg.max_requests)],
```

Add it to the returned dict and rewrite the docstring paragraph named above.

- [ ] **Step 5: Add the CLI option**

`--max-requests` on both `capture start` and `scan`, defaulting to the config's value so the flag overrides rather than replaces. A value below 1 is a `click.BadParameter`, not a silent clamp.

- [ ] **Step 6: Run both suites**

Run: `.venv/bin/pytest -q` then `.venv/bin/pytest -m integration -q`
Expected: your recorded baseline plus your new tests; integration unchanged. Report both lines.

The integration rig passes its own `limit.max_requests` and tests budget exhaustion. **If an integration test fails here, read it before touching it** — it is telling you the product now disagrees with the rig about the budget, and the product is the more likely to be wrong.

- [ ] **Step 7: Commit**

```bash
git add src/hx/config.py src/hx/session.py src/hx/cli.py tests/
git commit -m "feat(config): the request budget gets a number and a writer"
```

---

## Task 7: the probe pass

**Files:**
- Modify: `src/hx/scan.py`, `src/hx/checks/registry.py`, `src/hx/cli.py`
- Test: `tests/test_scan_probes.py` (create), `tests/test_registry.py`

**Interfaces:**
- Consumes: `probe.ProbeSender` and `probe.ProbeRefused` (Task 5); `insertion.derive(request_bytes, path_template) -> tuple[Insertion, ...]`; `session.session(eng, *, instance, jar=None, workdir=None)` yielding `LiveSession(operator_port, crawler_port, epoch, bridge, workdir)`.
- Produces: `scan.run(..., bridge=None)`; `"probes"` in `registry._RUNNER_CALLS`; `hx scan` opens a session when an active class is enabled.

**The registry left a note for this task.** `_HOOKS["active_safe"] = ("probes", "on_corpus")` already names the hook, and `_RUNNER_CALLS = ("on_surface",)` carries the comment *"WHEN A RUNNER PASS IS ADDED, ADD ITS HOOK HERE — this tuple is what makes such a check runnable, and forgetting"*. F7 of a previous review currently makes `validate()` **refuse** a check whose only hook the runner never calls; adding `"probes"` is what lifts that refusal for active checks.

**Dispatch on the hook, not on the class string.** `validate()` already guarantees each check implements exactly one runner-called hook and that its class permits it, so the runner asks which of `_RUNNER_CALLS` the check implements. A `klass == "passive"` string comparison would duplicate a rule the registry already owns and drift from it.

**The session is opened by the CLI, not by `scan.run`.** `scan.run` takes a `bridge` and never builds one — it has no engagement root, no jar, and no business owning a process. `hx scan` opens `session.session(...)` **only when `registry.enabled(config)` contains an active check**; a passive-only scan stays offline and must not pay Burp's startup. When no bridge is supplied and an active check is enabled, every active check records `skipped` with a reason naming the absence — never silence, per §12.

- [ ] **Step 1: Write the failing tests**

Sketch — adapt to `tests/test_scan.py`'s existing engagement fixtures.

```python
def test_an_active_check_is_handed_a_sender_and_its_insertion_points(engagement):
    seen = {}

    class Probe:
        id, version, klass = "hx.test.probe", "1", "active_safe"
        insertion_kinds = frozenset({"query"})

        def probes(self, ctx, surface, insertions, send):
            seen["insertions"] = insertions
            seen["sender"] = send
            return base.Verdict.clean(considered=("probed",))

    scan.run(conn, engagement_id=eng.id, config=cfg, blobs=blobs,
             checks=(Probe(),), bridge=_FakeBridge())
    assert seen["insertions"], "a check was handed no insertion points"
    assert isinstance(seen["sender"], probe.ProbeSender)


def test_an_active_check_without_a_bridge_is_skipped_not_silent(engagement):
    # S12: a report that cannot distinguish "tested, clean" from "never
    # reached" is worse than no report. No bridge means never reached.
    summary = scan.run(conn, engagement_id=eng.id, config=cfg, blobs=blobs,
                       checks=(Probe(),), bridge=None)
    row = conn.execute("SELECT verdict, reason FROM check_run").fetchone()
    assert row[0] == "skipped" and "bridge" in row[1]


def test_a_refusal_becomes_inconclusive_never_clean(engagement):
    class Refused:
        id, version, klass = "hx.test.refused", "1", "active_safe"
        insertion_kinds = frozenset({"query"})

        def probes(self, ctx, surface, insertions, send):
            raise probe.ProbeRefused("budget_exhausted")

    scan.run(..., checks=(Refused(),), bridge=_FakeBridge())
    row = conn.execute("SELECT verdict, reason FROM check_run").fetchone()
    assert row[0] == "inconclusive" and "budget_exhausted" in row[1]


def test_a_surface_with_no_insertion_points_is_skipped_with_a_reason(engagement):
    # Also never silence. A surface nothing could be probed on is a fact the
    # coverage section has to carry.
    ...


def test_requests_sent_is_written_when_the_row_closes(engagement):
    # The sender counts in memory; the runner writes the count. Assert the
    # stored number equals what the check actually spent.
    ...
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_scan_probes.py -v`
Expected: FAIL — `scan.run() got an unexpected keyword argument 'bridge'`.

- [ ] **Step 3: Add the hook to the registry**

```python
# src/hx/checks/registry.py -- Task 8: probes joins the hooks the runner calls
_RUNNER_CALLS = ("on_surface", "probes")
```

Update the comment above it: `probes` is now called, so the paragraph explaining why it was refused must say what changed rather than being deleted — the next person adding `on_corpus` needs the reasoning intact.

- [ ] **Step 4: Add the probe pass to `scan.run`**

Inside the existing per-surface loop, beside the passive dispatch. Derive insertion points **once per surface**, lazily, and only if an active check is enabled — `insertion.derive` parses the exemplar exchange and a passive-only scan must not pay for it. Build a `ProbeSender` per `check_run` row, call `check.probes(ctx, surface, insertions, sender)`, and on `ProbeRefused` close the row `inconclusive` with the refusal's reason. Write `sender.sent` into `check_run.requests_sent` when the row closes.

The existing `try` already wraps result handling as well as the call — keep that. A check that raises anything else still lands `error` and does not end the scan.

- [ ] **Step 5: Open the session in `hx scan`**

Only when `registry.enabled(config)` contains a check whose class is not `passive`. Pass `live.bridge` into `scan.run`. A `session.SessionError` becomes a `click.ClickException` with the message intact, as `capture start` does.

- [ ] **Step 6: Run both suites**

Run: `.venv/bin/pytest -q` then `.venv/bin/pytest -m integration -q`. Report both lines.

- [ ] **Step 7: Commit**

```bash
git add src/hx/scan.py src/hx/checks/registry.py src/hx/cli.py tests/
git commit -m "feat(scan): the probe pass, and the hook the registry was holding open"
```

---

## Task 8: CORS misconfiguration — the first check that sends

**Files:**
- Create: `src/hx/checks/active/__init__.py`, `src/hx/checks/active/cors.py`
- Modify: `src/hx/checks/registry.py` (add to `CHECKS`)
- Test: `tests/test_checks_cors.py`

**Interfaces:**
- Consumes: `probe.ProbeSender.get(path, *, headers=None, timeout=30.0) -> ProbeResponse`; `base.Verdict.clean(*, considered=())` / `base.Verdict.finding(*candidates, considered=())`.
- Produces: `cors.Cors` with `id = "hx.active.cors"`, `klass = "active_safe"`, `insertion_kinds = frozenset()`.

**This check goes first because it is the cheapest thing that proves the whole path.** One GET carrying an `Origin` header, and the answer is in the response headers — no payload, no reflection analysis, no insertion points. If this check works end to end, the probe pass, the sender, the registry and the report all work; every later check is then detection logic rather than plumbing.

`insertion_kinds` is empty because a CORS finding has no insertion point: the request is shaped by a header the check adds, not by a parameter it found. That is the same reason §5 gives for TLS and cookie-flag findings.

**What to send and what to conclude.** Send `Origin: https://<a value that cannot be the target>` and read `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` off the response. The severity depends on the pair: reflecting an arbitrary origin **with** credentials allowed is the serious case; reflecting it without credentials is weaker; `*` with credentials is refused by browsers and is a lower-severity misconfiguration rather than an exploitable one. Encode that reasoning in the check's docstring so a reader knows why the severities differ, and put the observed header values in the candidate's `description` — a client fixing this needs to see what was returned.

**Issue types.** Distinct, stable, lowercase-kebab, one per conclusion (for example `cors-reflects-arbitrary-origin-with-credentials` and `cors-wildcard-with-credentials`). They go in the dedupe key: renaming one later re-files every existing finding of that type as new.

`considered` must name **every** issue type this check can conclude about on a surface it examined, not merely the ones it emitted — that is what lets a fixed CORS header be retired on the next scan.

- [ ] **Step 1: Write the failing tests**

Sketch. Drive the check with a fake sender rather than a real Burp; the real-Burp path is Task 13's.

```python
def test_an_arbitrary_origin_reflected_with_credentials_is_a_finding():
    v = cors.Cors().probes(ctx, surface, (), _sender_returning(
        {"Access-Control-Allow-Origin": "https://evil.test",
         "Access-Control-Allow-Credentials": "true"}))
    assert v.state == "finding"
    assert "evil.test" in v.candidates[0].description


def test_a_target_that_ignores_the_origin_is_clean_and_says_what_it_considered():
    v = cors.Cors().probes(ctx, surface, (), _sender_returning({}))
    assert v.state == "clean"
    assert v.considered, "a clean answer that names nothing can never retire a fixed header"


def test_a_refusal_is_inconclusive_never_clean():
    with_refusing_sender = _sender_raising(probe.ProbeRefused("rate_limited"))
    v = cors.Cors().probes(ctx, surface, (), with_refusing_sender)
    assert v.state == "inconclusive" and "rate_limited" in v.reason


def test_the_check_sends_exactly_one_request():
    sender = _counting_sender()
    cors.Cors().probes(ctx, surface, (), sender)
    assert sender.sent == 1, "CORS needs one GET; more is budget spent for nothing"
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_checks_cors.py -v`
Expected: FAIL — `No module named 'hx.checks.active'`.

- [ ] **Step 3: Write the check and register it**

Follow `src/hx/checks/passive/security_headers.py` for file shape, docstring style and how candidates are built. Add the instance to `registry.CHECKS`; `validate()` runs at import and will refuse it if the class and hook disagree.

- [ ] **Step 4: Run the suite**

Run: `.venv/bin/pytest -q`. Report the line.

- [ ] **Step 5: Commit**

```bash
git add src/hx/checks/active tests/test_checks_cors.py src/hx/checks/registry.py
git commit -m "feat(checks): CORS misconfiguration, the first check that sends"
```

---

## Task 9: open redirect

**Files:**
- Create: `src/hx/checks/active/open_redirect.py`
- Modify: `src/hx/checks/registry.py`
- Test: `tests/test_checks_open_redirect.py`

**Interfaces:**
- Produces: `open_redirect.OpenRedirect`, `id = "hx.active.open-redirect"`, `klass = "active_safe"`, `insertion_kinds = frozenset({"query"})`.

**The safety rule this check must not break: never follow the redirect.** The send path is configured `RedirectionMode.NEVER`, and a check that followed a `Location` would be issuing a request the operator never authorised, against a host that may be out of scope — the exact shape §4 exists to prevent. Read `Location` and stop. Say so in the docstring, because "follow it to confirm" is the obvious next thought and it is wrong here.

**Canary-first.** Only probe query parameters whose name or current value suggests a redirect target; probing every parameter on every surface spends the budget on parameters that cannot redirect. Put an off-site marker value in the parameter, then examine the status and `Location`. A `Location` whose host is the marker's is the finding; a `Location` that keeps the target's host is not.

**Judge the marker carefully.** It must be a value that cannot plausibly belong to the target and cannot be reached if the check is wrong — a domain in a reserved or example range rather than a real third party. State in the docstring which you chose and why it cannot resolve to anything real.

- [ ] **Step 1: Write the failing tests**

Sketch.

```python
def test_a_location_pointing_at_the_marker_host_is_a_finding(): ...
def test_a_location_that_keeps_the_targets_host_is_clean(): ...
def test_a_relative_location_is_not_an_open_redirect(): ...
def test_the_check_never_requests_the_location_it_was_given():
    # The safety property. Assert the sender saw exactly the probe request
    # and never a second one aimed at the redirect target.
    ...
def test_a_parameter_that_cannot_redirect_is_not_probed():
    # Budget: canary-first means not every query parameter earns a request.
    ...
```

- [ ] **Step 2: Run to verify they fail**

Run the new test file. Expected: FAIL with the check's module missing.

- [ ] **Step 3: Write the check and register it**

Follow `src/hx/checks/passive/security_headers.py` for file shape and docstring style, and `src/hx/checks/passive/secret_in_response.py` for how a signature table is written and documented. Add the instance to `registry.CHECKS`; `validate()` runs at import and refuses a check whose class and hook disagree.

- [ ] **Step 4: Run the suite**

Run: `.venv/bin/pytest -q`. Report the line you actually saw.

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(checks): open redirect, read the Location and never follow it"
```

---

## Task 10: reflected input

**Files:**
- Create: `src/hx/checks/active/reflected_input.py`, `src/hx/checks/active/_probe_util.py`
- Modify: `src/hx/checks/registry.py`
- Test: `tests/test_checks_reflected_input.py`, `tests/test_probe_util.py`

**Interfaces:**
- Produces: `reflected_input.ReflectedInput`, `id = "hx.active.reflected-input"`, `klass = "active_safe"`, `insertion_kinds = frozenset({"query", "path_segment", "header", "cookie"})`; `_probe_util.canary()` and `_probe_util.reflected(response, marker)`.

**`_probe_util` exists because three checks would otherwise each grow their own copy** of canary minting and reflection testing. Keep it to what is genuinely shared; a helper used once belongs in its caller.

**The canary must be unmistakable and inert.** A marker that could occur naturally in a response produces false positives; a marker containing characters that could execute produces a payload rather than a probe. Mint something random, long enough not to collide, alphanumeric, and different per insertion point so two reflections cannot be confused. `active_safe` is idempotent GET/HEAD by §10 — this check reports **that input is reflected**, not that it is exploitable, and its severity and description must say so honestly rather than claiming XSS it did not prove.

**Escalate only on evidence.** One canary per insertion point. If it comes back, spend further requests characterising the context — where in the document it landed, and whether the characters that would matter survive. Say in the docstring what the escalation costs and what it concludes.

- [ ] **Step 1: Write the failing tests**

Sketch.

```python
def test_a_canary_that_comes_back_is_a_finding_naming_the_insertion_point(): ...
def test_a_canary_that_does_not_come_back_is_clean(): ...
def test_a_clean_answer_names_every_insertion_point_it_probed():
    # Otherwise a fixed parameter can never be retired.
    ...
def test_each_insertion_point_gets_its_own_canary():
    # Two points sharing a marker make one reflection look like two.
    ...
def test_one_request_per_point_until_something_reflects():
    # Canary-first: assert the budget spent on a surface that reflects
    # nothing equals the number of insertion points, not a multiple of it.
    ...
def test_the_finding_does_not_claim_exploitability_it_did_not_prove(): ...
```

- [ ] **Step 2: Run to verify they fail**

Run the new test file. Expected: FAIL with the check's module missing.

- [ ] **Step 3: Write the check and register it**

Follow `src/hx/checks/passive/security_headers.py` for file shape and docstring style, and `src/hx/checks/passive/secret_in_response.py` for how a signature table is written and documented. Add the instance to `registry.CHECKS`; `validate()` runs at import and refuses a check whose class and hook disagree.

- [ ] **Step 4: Run the suite**

Run: `.venv/bin/pytest -q`. Report the line you actually saw.

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(checks): reflected input, canary-first"
```

---

## Task 11: SQL error and path traversal

**Files:**
- Create: `src/hx/checks/active/sql_error.py`, `src/hx/checks/active/path_traversal.py`
- Modify: `src/hx/checks/registry.py`
- Test: `tests/test_checks_sql_error.py`, `tests/test_checks_path_traversal.py`

**Interfaces:**
- Consumes: `probe.ProbeSender.get(path, *, headers=None, timeout=30.0) -> ProbeResponse`; `base.Verdict.clean(*, considered=())` / `finding(*candidates, considered=())`; and **`_probe_util.canary()` / `_probe_util.reflected(response, marker)`, created in Task 10** — both checks here send a value and match the response, which is the shape that helper exists for. Do not reimplement it.
- Produces: `sql_error.SqlError` (`id = "hx.active.sql-error"`) and `path_traversal.PathTraversal` (`id = "hx.active.path-traversal"`), both `klass = "active_safe"`, both `insertion_kinds = frozenset({"query", "path_segment"})`.

**Two checks in one task because they are the same shape**: send a value at an insertion point, then match the response against a signature table. They differ only in the value and the table, and a reviewer can reject one while approving the other by file.

**SQL error.** Send a syntax-breaking character and look for database error signatures in the response — the vendor-specific text a driver emits when a query does not parse. The finding is *the application disclosed a database error*, which is what was observed; it is evidence of injection, not proof of it, and the description must not overstate. Signatures go in a module-level table with the vendor named per entry, so a reader can see what matched. Follow `secret_in_response.py` for how a pattern table is written and documented in this codebase.

**Path traversal.** Send a traversal sequence at a parameter that looks like it names a file, and look for file-content signatures. **Do not send a sequence that could reach outside the target's document root on a server that is not vulnerable** — read what the response contains, and prefer a signature that only a successful traversal would produce.

**Both must respect the budget.** A signature table with forty entries does not mean forty requests: one probe per insertion point, then match the single response against every signature.

- [ ] **Step 1: Write the failing tests** for both, in their own files. Each needs: a positive case, a negative case, a `considered`-names-what-it-probed case, a one-request-per-point case, and a case proving the finding's text does not claim more than was observed.

- [ ] **Step 2: Run to verify they fail**

Run the new test file. Expected: FAIL with the check's module missing.

- [ ] **Step 3: Write the check and register it**

Follow `src/hx/checks/passive/security_headers.py` for file shape and docstring style, and `src/hx/checks/passive/secret_in_response.py` for how a signature table is written and documented. Add the instance to `registry.CHECKS`; `validate()` runs at import and refuses a check whose class and hook disagree.

- [ ] **Step 4: Run the suite**

Run: `.venv/bin/pytest -q`. Report the line you actually saw.

- [ ] **Step 5: Commit**

Commit the two checks separately — a reviewer must be able to reject one and approve the other.

```bash
git commit -m "feat(checks): SQL error disclosure"
git commit -m "feat(checks): path traversal"
```

---

## Task 12: the report stops saying no active checks exist

**Files:**
- Modify: `src/hx/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `registry.CHECKS`.
- Produces: no new interface.

**Three statements in the report become false the moment Task 8 lands**, and a previous review established the standard: a sentence that *discloses a limitation* may be typed if a test holds it against the spec that mandates it; a sentence that *excuses an absence* should be removed rather than guarded.

1. The **Limits** bullet saying "This build ships no active checks, so no request carrying a payload was ever issued." Derive it from `registry.CHECKS` or remove it. It is now false in a way that matters: the report would tell a client no payload was issued while `check_run.requests_sent` says otherwise.
2. The **insertion-coverage** section, which renders derived points as *not probed*. Points this build now probes must not be reported as unprobed; points it still cannot reach — `body_form` and `body_json`, unreachable under a GET-only method allowlist — must still be reported as unprobed, and the existing Limits bullet about request-body parameters stays **true and must stay**.
3. The **unshipped-class note** for `active_safe`, which must stop appearing now that the class ships checks. `active_timing` is still enabled by default and still ships nothing, so its note must remain — that is the case the note exists for.

**The passive-retest disclosure must survive.** It says every check in this build is passive and reads the engagement's whole captured history, so a finding cannot be retired by re-browsing. That is about to be **half** true: active checks genuinely re-probe, so their findings *can* be retired. Rewrite it to say which half is which, rather than deleting a limitation that still binds the passive corpus.

- [ ] **Step 1: Write the failing tests**

Sketch — follow `tests/test_report.py`'s existing render fixtures.

```python
def test_the_limits_section_does_not_claim_no_active_checks_exist(rendered):
    assert "ships no active checks" not in rendered


def test_an_active_check_registered_makes_the_prose_change(monkeypatch):
    # The deliverable is a test that fails when the claim goes false, not the
    # wording. Registering an active check must move the text.
    ...


def test_body_parameters_are_still_reported_as_unprobed(rendered):
    # GET-only method allowlist; this limitation did not go away.
    ...


def test_active_timing_still_gets_its_unshipped_class_note(rendered):
    # Enabled by default, ships nothing. The note exists for exactly this.
    ...


def test_the_retest_disclosure_distinguishes_passive_from_active(rendered):
    ...
```

- [ ] **Step 2-5:** Run to verify failure, implement, run the suite, commit.

```bash
git commit -m "fix(report): the deliverable stops claiming no active checks exist"
```

---

## Task 13: end to end against a real Burp

**Files:**
- Modify: `tests/integration/target_server.py`
- Create: `tests/integration/test_active_checks.py`
- Test: the integration suite is the test.

**Interfaces:**
- Consumes: everything.

**The target grows endpoints that are genuinely vulnerable, on loopback.** Reflect a query parameter into the response body; return database error text when a parameter contains a quote; expose a traversal; redirect off-site from a parameter; return permissive CORS headers for an arbitrary `Origin`. Each must be reachable by GET, because that is all `active_safe` may send.

**These are the first tests in this project that send attack traffic.** Nothing here has ever sent a request off this machine, and the loopback guarantee stops being incidental: it is now the thing standing between a test suite and someone else's server. Every endpoint is on the fixture's loopback target and no test may take a hostname from anywhere else.

- [ ] **Step 1: Add the vulnerable endpoints** to `target_server.py`, each with a comment saying which check it exists for.

- [ ] **Step 2: Write the end-to-end test**

`hx capture start` → browse the vulnerable surfaces → `hx scan` with `active_safe` enabled → assert each check found its finding, that `check_run.requests_sent` is non-zero and bounded, and that the report renders them.

Then the property that matters most and that no unit test can reach: **run the scan twice, fix nothing, and assert the findings are stable** — one row per issue, not two. Then fix one endpoint in the fixture, re-scan, and assert **that finding retires** while the others stay live. That is `Verdict.considered` and the retirement change working end to end, and it is the half of §12's retest story that the passive corpus cannot deliver.

- [ ] **Step 3: Run everything**

```bash
.venv/bin/pytest -q
.venv/bin/pytest -m integration -q
./extension/test.sh 2>&1 | tail -3
```

Report all three, and for Java report the **output line count** as well as the result — it has printed zero summary lines and exited 0 with a missing jar.

- [ ] **Step 4: Confirm no Burp survived**

```bash
ps -eo pid,args | grep '[j]ava.*StartBurp' || echo none
```

- [ ] **Step 5: Commit**

```bash
git add tests/integration
git commit -m "test(integration): the active corpus against a real target"
```

- [ ] **Step 6: Mark this plan's code blocks and sync them**

Now that every file this plan describes exists, give each block meant to be transcribed verbatim a `# path` marker on its first line — `path` for a whole file, `path -- note` for an excerpt — and sync with `scripts/sync_plan_block.py`. Then run `.venv/bin/pytest tests/test_plan_matches_repo.py -q` and confirm the new blocks are **compared and matching**, not merely absent.

This step exists because the previous plan shipped with **zero** compared blocks: one was restructured mid-flight to dodge a marker error and nobody noticed until the whole-branch review counted them. Report how many blocks this plan now contributes.

```bash
git add docs/superpowers/plans/2026-08-29-active-checks.md
git commit -m "chore(plans): mark and sync this plan's blocks against the shipped code"
```
