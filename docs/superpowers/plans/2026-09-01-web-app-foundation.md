# Web app foundation — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A loopback-only Starlette app that reads an engagement store and
gives a human the two acts the agent is forbidden — confirming a finding
and hitting STOP.

**Architecture:** `src/hx/web/` owns its own read queries against
`store.db.connect(readonly=True)`, a fresh connection per request. It never
calls `tools/dispatch.py` (which journals every call as the agent) and never
sends a byte to a target. Writes are two POST routes over `src/hx/triage.py`
(new) and `halt.OperatorHalt` (existing, unchanged).

**Tech Stack:** Python 3.12, Starlette, Jinja2, uvicorn, vendored htmx,
SQLite. No build step, no SPA, no `node_modules`.

**Spec:** `docs/superpowers/specs/2026-09-01-web-app-design.md`
(approved 2026-09-01, commit `6d26738`).
**Master spec:** `docs/superpowers/specs/2026-08-21-hx-design.md`
(§4 enforcement invariant, §5 data model, §7 redaction, §8 human acts,
§11 web app as amended to Starlette, §12 reporting, §13 v1 scope).

## Global Constraints

Every task's requirements implicitly include this section.

- **Python 3.12.** `from __future__ import annotations` at the top of every
  new module, matching the tree.
- **Runtime dependencies become exactly:** `PyYAML>=6.0`, `click>=8.1`,
  `starlette>=0.47`, `jinja2>=3.1`, `uvicorn>=0.35`. Installed closure is 10
  packages: `anyio click h11 idna jinja2 markupsafe pyyaml starlette
  typing-extensions uvicorn`. **Do not add `fastapi`, `pydantic`, `httpx`, or
  `python-multipart` to runtime deps.** `httpx` goes in the `dev` group only.
- **No new integration tests.** The web app never touches Burp. The
  `integration` marker stays at 46 tests.
- **`ruff check src tests` must pass**, and ruff's `select = ["E4","E7","E9","F"]`
  **excludes E501**, so a clean ruff run does NOT prove line length. Check
  with `awk 'length>88 {print FILENAME": "FNR}' <files>` before every commit.
- **This plan must NOT carry `plan-drift: pending`.**
  `2026-08-27-checks-and-reporting.md` already holds it and at most one plan
  may. Code blocks in this plan therefore carry **no `# path` marker line**
  while the plan is being executed; the final section arms them.
- **Never widen a permission.** Engagement directories stay `0700`, database
  and blobs `0600`. This plan creates no files inside an engagement except
  the halt sentinel, which `OperatorHalt` already writes at `0600`.
- **The app binds `127.0.0.1` only.** There is no `--host` option, and adding
  one is out of scope.
- **A credential value never appears** in a rendered page, a log line, or an
  exception message. Blob bytes are already redacted extension-side; URL
  columns go through `records.redact_url` and nothing else.
- **Every security test must be written so a named mutation turns it red.**
  This repo has shipped vacuous tests twice — a cap asserted against a value
  that never reached it, and a constant asserted against itself. Each
  security test in this plan names its mutation; if you cannot state the
  mutation, the test is not finished.

---

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `src/hx/coverage.py` | The coverage facts, as data. One implementation, rendered by both the report and the overview screen. |
| `src/hx/triage.py` | The only writer of `finding_status_event`. `actor='human'`, hardcoded. |
| `src/hx/web/__init__.py` | Empty package marker. |
| `src/hx/web/registry.py` | Scans the base directory; the scan **is** the traversal allowlist. |
| `src/hx/web/reads.py` | Read-only queries, one function per screen. |
| `src/hx/web/render.py` | The Jinja environment and its filters. |
| `src/hx/web/app.py` | App factory, security middleware, routes. |
| `src/hx/web/templates/*.html` | One per screen, plus `base.html`. |
| `src/hx/web/static/` | Vendored htmx and one stylesheet. |
| `tests/test_coverage.py` | The extraction preserves behaviour. |
| `tests/test_triage.py` | The status writer. |
| `tests/test_cli_triage.py` | The CLI command. |
| `tests/test_web_registry.py` | Discovery and the allowlist. |
| `tests/test_web_security.py` | The seven invariants of spec §4. |
| `tests/test_web_screens.py` | Each screen shows the right data. |
| `tests/test_credentials_never_reach_the_screen.py` | Mirrors `test_credentials_never_reach_the_store.py`. |

**Modified:**

| File | Change |
|---|---|
| `pyproject.toml` | Runtime and dev dependencies. |
| `src/hx/run.py` | `stale_before_us` and `is_stale` extracted; `reap_stale` uses them. |
| `src/hx/report.py` | `_coverage` and `_untested_surfaces` read from `hx.coverage`; `_findings` renders the triage note. |
| `src/hx/cli.py` | `hx web` and `hx triage`. |
| `tests/conftest.py` | `web_base` and `client` fixtures. |
| `docs/DECISIONS.md` | The web-app chapter and its debt rows. |
| `README.md` | The `hx web` and `hx triage` sections. |

`reads.py` is the file to watch. If it passes roughly 400 lines it should
split per screen rather than become the module that knows everything.

---

## The plan-drift gate

`tests/test_plan_matches_repo.py` byte-compares every fenced ```python /
```java / ```sql block whose **first line** is a `# <path>` marker against
the file it names. A block for a file that does not exist yet is skipped; a
block for a file that *does* exist and differs is a failure.

While this plan is being executed its blocks carry **no marker**, so none is
compared. The final section arms them in one pass, once every file exists.
`html`, `bash` and `toml` fences are never scanned, so templates, shell
blocks and the dependency edit need nothing.

**A trap, hit while writing this plan.** `_is_pending` asks whether the
literal HTML comment appears **in the first 40 lines** of the file — so a
plan that merely *mentions* the marker near its top is read as carrying it,
and `test_at_most_one_plan_is_pending` fails with two plans named. That is
why this document never spells the marker out, referring to
`plan-drift: pending` without its comment delimiters. Keep it that way when
you edit this file.

---

## Task 1: Shared coverage facts and one definition of "stale"

Two extractions with no consumer yet. Both take merged, tested code and pull
a decision out of it so a second caller can share it rather than write a
second version. The existing suites (`tests/test_report.py`,
`tests/test_run.py`) are the safety net: behaviour must not move.

**Files:**
- Create: `src/hx/coverage.py`
- Create: `tests/test_coverage.py`
- Modify: `src/hx/run.py` (add `stale_before_us`, `is_stale`; rewrite `reap_stale`'s selection)
- Modify: `src/hx/report.py` (`_coverage`, `_untested_surfaces`, `render`)
- Test: `tests/test_coverage.py`, and `tests/test_report.py` / `tests/test_run.py` unchanged and still green

**Interfaces:**
- Consumes: `hx.store.db.transaction`, `hx.engagement.now_us`
- Produces, for Tasks 3-7:
  - `hx.coverage.ANSWERED: tuple[str, ...]`
  - `hx.coverage.Coverage` — frozen dataclass with fields `captured: int`,
    `scanned: bool`, `unfinished: tuple[tuple, ...]`,
    `untested: tuple[tuple[str, str], ...]`,
    `by_check: tuple[tuple[str, str, int], ...]`,
    `reasons: dict[tuple[str, str], list[str]]`
  - `hx.coverage.facts(conn, engagement_id) -> Coverage`
  - `hx.coverage.unshipped_classes(config) -> tuple[str, ...]`
  - `hx.run.stale_before_us(*, now_us=None, stale_after_us=None) -> int`
  - `hx.run.is_stale(status, heartbeat_us, started_us, *, before_us) -> bool`

- [ ] **Step 1: Write the failing test for `is_stale`**

Create `tests/test_coverage.py` with the staleness cases first — they are the
smaller half and they pin the NULL-heartbeat rule that `reap_stale`'s comment
exists to protect.

```python
"""The two extractions Task 1 makes, and the behaviour they must not move."""
from __future__ import annotations

from hx import run as run_mod


def test_a_completed_run_is_never_stale():
    """Staleness is a property of `running` runs only. A completed run's
    heartbeat stopped because the run ended, which is not a dead harness."""
    assert run_mod.is_stale("completed", 0, 0, before_us=10_000) is False


def test_a_running_run_with_a_fresh_heartbeat_is_not_stale():
    assert run_mod.is_stale("running", 20_000, 0, before_us=10_000) is False


def test_a_running_run_with_an_old_heartbeat_is_stale():
    assert run_mod.is_stale("running", 5_000, 0, before_us=10_000) is True


def test_a_run_that_never_heartbeated_falls_back_to_started_us():
    """The case `reap_stale`'s COALESCE exists for: `heartbeat_us` is
    NULLable, and a run that died BEFORE its first heartbeat is precisely
    what the mechanism is for. In SQL `NULL < x` is NULL and WHERE treats
    that as false, so such a run would never be reaped."""
    assert run_mod.is_stale("running", None, 5_000, before_us=10_000) is True
    assert run_mod.is_stale("running", None, 20_000, before_us=10_000) is False


def test_the_window_is_twice_the_idle_close():
    """Deliberately WIDER than IDLE_CLOSE_US: an idle run is one nobody used,
    a stale one is a run whose process is gone. Reaping at the idle boundary
    would file every ordinary pause as a crash."""
    assert run_mod.stale_before_us(now_us=1_000_000_000) == (
        1_000_000_000 - run_mod.IDLE_CLOSE_US * 2)
    assert run_mod.stale_before_us(now_us=500, stale_after_us=100) == 400
```

- [ ] **Step 2: Run it to verify it fails**

```bash
.venv/bin/pytest tests/test_coverage.py -q
```

Expected: FAIL, `AttributeError: module 'hx.run' has no attribute 'is_stale'`.

- [ ] **Step 3: Add `stale_before_us` and `is_stale` to `src/hx/run.py`**

Insert both immediately **above** `def reap_stale`, so the predicate reads
before its first caller.

```python
def stale_before_us(*, now_us: int | None = None,
                    stale_after_us: int | None = None) -> int:
    """The heartbeat a `running` run must be newer than to count as alive.

    Deliberately a WIDER window than IDLE_CLOSE_US: an idle run is one nobody
    used, and a stale one is a run whose process is gone. Reaping at the idle
    boundary would file every ordinary pause as a crash.
    """
    at = _now_us() if now_us is None else now_us
    window = IDLE_CLOSE_US * 2 if stale_after_us is None else stale_after_us
    return at - window


def is_stale(status: str, heartbeat_us: int | None, started_us: int,
             *, before_us: int) -> bool:
    """Whether one run row is a run whose harness died.

    ONE DEFINITION, because there are now two callers and they must not be
    free to disagree. `reap_stale` below resolves such a run to `error` in
    the store; the web app's overview screen RENDERS it as `error` without
    writing anything, since its connections are read-only. A screen that
    showed `running` for a run the reaper would kill is the first thing an
    operator sees after a crash, and S5 is explicit: "an aborted run must
    never render as a clean one, and neither must one that merely STOPPED
    BEING UPDATED".

    The `heartbeat_us or started_us` fallback is what `reap_stale`'s SQL
    spelled `COALESCE`, and it is load-bearing for the same reason: the
    column is NULLable, and a run that died BEFORE its first heartbeat is
    precisely what this mechanism is for. `started_us` is NOT NULL, so a run
    that started long ago and never reported is stale on its own evidence.
    """
    if status != "running":
        return False
    last = started_us if heartbeat_us is None else heartbeat_us
    return last < before_us
```

- [ ] **Step 4: Rewrite `reap_stale`'s selection to use them**

Replace the body of `reap_stale` (its docstring's first line stays; the
COALESCE comment is replaced because the COALESCE is gone).

```python
def reap_stale(conn: sqlite3.Connection, *, now_us: int | None = None,
               stale_after_us: int | None = None) -> list[str]:
    """Resolve runs whose harness died to `error`. Returns their ids.

    THE PREDICATE MOVED OUT, to `is_stale` above, and the SQL got simpler
    rather than smarter: this selects every `running` run and filters in
    Python. The previous version asked SQLite
    `COALESCE(heartbeat_us, started_us) < ?`, which was correct and was also
    a SECOND copy of a rule the web app's read-only overview screen needs to
    apply without writing. Two spellings of "stale" in two languages is how
    a screen and a reaper end up disagreeing about the same run. The set
    being filtered is every run currently `running` in one engagement, which
    is nought or one in practice and never large.
    """
    at = _now_us() if now_us is None else now_us
    before = stale_before_us(now_us=at, stale_after_us=stale_after_us)
    rows = conn.execute(
        "SELECT id, heartbeat_us, started_us FROM run WHERE status='running'"
    ).fetchall()
    ids = [r[0] for r in rows if is_stale("running", r[1], r[2],
                                          before_us=before)]
    for run_id in ids:
        conn.execute(
            "UPDATE run SET status='error', ended_us=?, stop_reason=?"
            " WHERE id=? AND status='running'",
            (at, "heartbeat went stale: the harness stopped without closing "
                 "this run, so its coverage is incomplete", run_id))
    return ids
```

- [ ] **Step 5: Verify the extraction moved no behaviour**

```bash
.venv/bin/pytest tests/test_coverage.py tests/test_run.py -q
```

Expected: PASS, and `tests/test_run.py` unmodified. If any test in
`test_run.py` needed changing, the extraction changed behaviour — stop and
say so rather than editing the test.

- [ ] **Step 6: Commit**

```bash
git add src/hx/run.py tests/test_coverage.py
git commit -m "refactor(run): one definition of stale, for a reader that cannot write"
```

- [ ] **Step 7: Write the failing test for the coverage facts**

Append to `tests/test_coverage.py`. These assert against a store built by
hand, so they pin the numbers rather than the phrasing — the report's own
suite already pins the phrasing.

```python
import sqlite3

import pytest

from hx import coverage as coverage_mod
from hx import config as config_mod
from hx.store import db as db_mod


def _store(tmp_path):
    conn = db_mod.connect(tmp_path / "hx.db")
    db_mod.init_schema(conn)
    conn.execute("INSERT INTO engagement(id, name, client, created_us, status)"
                 " VALUES('e1','t','T',0,'active')")
    return conn


def _surface(conn, sid, method, template):
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES(?,?,?,'https','app.test',443,?,'proxy',2)",
        (sid, "e1", method, template))


def _run(conn, rid, status="completed"):
    conn.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status, requests_issued, dropped_total) VALUES(?,?,'scan','staging',"
        "0,?,0,0)", (rid, "e1", status))


def _check_run(conn, cid, rid, sid, check_id, verdict, reason=None):
    conn.execute(
        "INSERT INTO check_run(id, run_id, surface_id, check_id, check_version,"
        " verdict, reason) VALUES(?,?,?,?,'1',?,?)",
        (cid, rid, sid, check_id, verdict, reason))


def test_an_empty_engagement_has_no_coverage_and_says_so(tmp_path):
    conn = _store(tmp_path)
    cov = coverage_mod.facts(conn, "e1")
    assert cov.captured == 0
    assert cov.scanned is False
    assert cov.untested == ()
    assert cov.by_check == ()


def test_a_surface_with_only_a_skipped_row_counts_as_untested(tmp_path):
    """The separating case. A `pending` row means the runner opened it and
    the process died; a `skipped` row means the budget cut the scan off
    before it. Reading either as coverage is S12's failure in the direction
    that matters -- a row that exists to record a GAP read as an answer."""
    conn = _store(tmp_path)
    _surface(conn, "s1", "GET", "/a")
    _surface(conn, "s2", "GET", "/b")
    _run(conn, "r1")
    _check_run(conn, "c1", "r1", "s1", "missing-hsts", "clean")
    _check_run(conn, "c2", "r1", "s2", "missing-hsts", "skipped")

    cov = coverage_mod.facts(conn, "e1")
    assert cov.captured == 2
    assert cov.scanned is True
    assert [tuple(r) for r in cov.untested] == [("GET", "/b")]


def test_a_surface_retested_across_runs_is_counted_once(tmp_path):
    """F5 of the report's own review: `COUNT(DISTINCT surface_id)`, not
    `COUNT(*)`. A `check_run` row exists per (surface, check) PER RUN, so
    counting rows makes three surfaces scanned twice render as 6. The error
    is always upward, the one direction a coverage figure must not lie in."""
    conn = _store(tmp_path)
    _surface(conn, "s1", "GET", "/a")
    _run(conn, "r1")
    _run(conn, "r2")
    _check_run(conn, "c1", "r1", "s1", "missing-hsts", "clean")
    _check_run(conn, "c2", "r2", "s1", "missing-hsts", "clean")

    cov = coverage_mod.facts(conn, "e1")
    assert [tuple(r) for r in cov.by_check] == [("missing-hsts", "clean", 1)]


def test_reasons_are_grouped_commonest_first(tmp_path):
    conn = _store(tmp_path)
    for n in ("s1", "s2", "s3"):
        _surface(conn, n, "GET", f"/{n}")
    _run(conn, "r1")
    _check_run(conn, "c1", "r1", "s1", "cors", "inconclusive", "no origin")
    _check_run(conn, "c2", "r1", "s2", "cors", "inconclusive", "no origin")
    _check_run(conn, "c3", "r1", "s3", "cors", "inconclusive", "budget")

    cov = coverage_mod.facts(conn, "e1")
    assert cov.reasons[("cors", "inconclusive")] == ["no origin", "budget"]


def test_a_running_run_counts_as_unfinished(tmp_path):
    """`status <> 'completed'`, so all four of running | aborted | killed |
    error are caught and a value added to the CHECK later cannot slip
    through as finished. `running` is deliberate: S5 says a run left running
    is a dead harness, and one genuinely in flight has produced partial
    coverage too."""
    conn = _store(tmp_path)
    _run(conn, "r1", status="running")
    _run(conn, "r2", status="completed")

    cov = coverage_mod.facts(conn, "e1")
    assert [r[0] for r in cov.unfinished] == ["r1"]


def test_an_enabled_class_the_build_ships_nothing_for_is_named():
    """F11 of the report's review. A check class the operator enabled and
    this build has no checks in leaves no `check_run` row, so it leaves no
    trace in the table -- and silence there reads as coverage."""
    cfg = config_mod.Config(name="t", client="T", safety_profile="staging",
                            scope_include=["https://app.test/*"])
    cfg.checks["nonexistent_class"] = True
    assert "nonexistent_class" in coverage_mod.unshipped_classes(cfg)
```

- [ ] **Step 8: Run it to verify it fails**

```bash
.venv/bin/pytest tests/test_coverage.py -q
```

Expected: FAIL, `ModuleNotFoundError: No module named 'hx.coverage'`.

- [ ] **Step 9: Create `src/hx/coverage.py`**

```python
"""The coverage facts, computed once and rendered twice.

S12 -- "a report that cannot distinguish 'tested, clean' from 'never
reached' is worse than no report" -- is carried by a handful of numbers, and
the way to break it is not to get one of them wrong. It is to compute them
TWICE, in two places, and let the two drift. `report._coverage` had these
queries fused with its Markdown; the web app's overview screen needs the
same figures in HTML. A second implementation would lose what this one
learned the hard way -- the denominator, the NAMED untested surfaces, and
the "these numbers are partial" prefix -- and would show a reassuring
number on exactly the engagements where the report shows a warning.

`scanned` and `unfinished` are computed HERE, alongside the rest, for the
reason `report.render` already computes them once and passes them down:
several sections make a statement about each and none may be free to
disagree with the others.

WHAT THIS MODULE DOES NOT DO IS RENDER. It returns data. `report._coverage`
turns it into Markdown and the overview template turns it into HTML, and
neither is the other's business.
"""
from __future__ import annotations

import dataclasses
import sqlite3

from hx.checks import registry

#: A `check_run.verdict` that means a check actually ANSWERED for a surface.
#: `pending` (the runner opened the row and the process died) and `skipped`
#: (the budget cut the scan off before it) are rows that record a GAP, and
#: counting either as coverage reads a gap as an answer.
ANSWERED = ("clean", "finding", "inconclusive", "error")


@dataclasses.dataclass(frozen=True)
class Coverage:
    """Every number the coverage story is told with.

    `untested` and `unfinished` are rows, not counts, because both are lists
    a reader acts on: the surfaces nothing answered for, and the runs whose
    numbers are a floor. A count alone is what S12 calls unfalsifiable.
    """

    captured: int
    scanned: bool
    unfinished: tuple
    untested: tuple
    by_check: tuple
    reasons: dict


def facts(conn: sqlite3.Connection, engagement_id: str) -> Coverage:
    """Read every coverage figure for one engagement, in one place."""
    captured = conn.execute(
        "SELECT COUNT(*) FROM surface WHERE engagement_id=?",
        (engagement_id,)).fetchone()[0]

    scanned = bool(conn.execute(
        "SELECT 1 FROM check_run cr JOIN run r ON r.id = cr.run_id"
        " WHERE r.engagement_id=? LIMIT 1", (engagement_id,)).fetchone())

    unfinished = tuple(conn.execute(
        "SELECT id, kind, status, stop_reason, started_us FROM run"
        " WHERE engagement_id=? AND status <> 'completed'"
        " ORDER BY started_us, id", (engagement_id,)).fetchall())

    marks = ",".join("?" for _ in ANSWERED)
    untested = tuple(conn.execute(
        "SELECT s.method, s.path_template FROM surface s"
        " WHERE s.engagement_id=? AND NOT EXISTS ("
        "   SELECT 1 FROM check_run cr JOIN run r ON r.id = cr.run_id"
        "   WHERE cr.surface_id = s.id AND r.engagement_id = s.engagement_id"
        f"    AND cr.verdict IN ({marks}))"
        " ORDER BY s.path_template, s.method, s.id",
        (engagement_id, *ANSWERED)).fetchall())

    # COUNT(DISTINCT surface_id), not COUNT(*): a `check_run` row exists per
    # (surface, check) PER RUN, so counting rows counts a retested surface
    # once per run it was retested in -- three surfaces scanned twice
    # rendered "6". The error is always upward, the one direction a coverage
    # figure must not lie in.
    by_check = tuple(conn.execute(
        "SELECT cr.check_id, cr.verdict, COUNT(DISTINCT cr.surface_id)"
        " FROM check_run cr"
        " JOIN run r ON r.id = cr.run_id WHERE r.engagement_id=?"
        " GROUP BY cr.check_id, cr.verdict"
        " ORDER BY cr.check_id, cr.verdict", (engagement_id,)).fetchall())

    # Ordered by how many surfaces recorded each reason, then by the reason
    # text -- so the one a reader most needs is the one that survives a
    # caller's cap, and the tiebreak is stable across renders.
    reasons: dict = {}
    for check_id, verdict, reason, _surfaces in conn.execute(
            "SELECT cr.check_id, cr.verdict, cr.reason,"
            " COUNT(DISTINCT cr.surface_id) AS n FROM check_run cr"
            " JOIN run r ON r.id = cr.run_id WHERE r.engagement_id=?"
            " AND cr.reason IS NOT NULL AND cr.reason <> ''"
            " GROUP BY cr.check_id, cr.verdict, cr.reason"
            " ORDER BY cr.check_id, cr.verdict, n DESC, cr.reason",
            (engagement_id,)).fetchall():
        reasons.setdefault((check_id, verdict), []).append(reason)

    return Coverage(captured=captured, scanned=scanned, unfinished=unfinished,
                    untested=untested, by_check=by_check, reasons=reasons)


def unshipped_classes(config) -> tuple:
    """Check classes this engagement enables that this build ships none of.

    Not a query: it is a fact about the BUILD and this engagement's config,
    true whether or not a scan has ever run. It belongs beside the coverage
    numbers because it is the one gap they cannot show -- a class with no
    checks in it leaves no `check_run` row, so it leaves no trace in the
    table, and silence there reads as coverage.
    """
    return tuple(sorted(
        klass for klass, on in config.checks.items()
        if on and not any(c.klass == klass for c in registry.CHECKS)))
```

- [ ] **Step 10: Run the new tests**

```bash
.venv/bin/pytest tests/test_coverage.py -q
```

Expected: PASS.

- [ ] **Step 11: Point `report.py` at the shared module**

Four edits, and `tests/test_report.py` must not need a single change.

**(a)** Add the import beside the others near line 70:

```python
from hx import coverage as coverage_mod
```

**(b)** Delete `_ANSWERED` (line 121) and the whole of `_untested_surfaces`,
`_reasons_by_row` and `_unfinished_runs`. Their queries now live in
`coverage.facts`.

**(c)** In `render`, replace the `scanned` and `unfinished` computations with
one call, keeping the comment that explains why they are computed once:

```python
    # ONE SOURCE OF TRUTH FOR THE COVERAGE FIGURES, shared by `_findings`
    # (F4 of fix round 1: an unscanned engagement's "None recorded" must not
    # read as a clean bill), `_coverage` (the original "not been scanned"
    # paragraph) and -- since 2026-09-01 -- the web app's overview screen.
    # Computed once here rather than several times, differently, in
    # functions that would otherwise be free to quietly disagree.
    cov = coverage_mod.facts(conn, engagement_id)

    out.extend(_provenance(conn, engagement_id, config, created_us=eng[3],
                           unfinished=cov.unfinished))
    out.extend(_findings(conn, engagement_id, scanned=cov.scanned,
                         unfinished=cov.unfinished))
    out.extend(_coverage(conn, engagement_id, config, cov=cov))
```

**(d)** Change `_coverage`'s signature to `def _coverage(conn, engagement_id,
config, *, cov) -> list[str]:` and replace its first two statements and its
three query sites with reads off `cov`:

| Was | Becomes |
|---|---|
| `captured = conn.execute(...)` | `captured = cov.captured` |
| `untested = _untested_surfaces(conn, engagement_id)` | `untested = cov.untested` |
| `if unfinished:` | `if cov.unfinished:` |
| `f"{len(unfinished)} of the "` | `f"{len(cov.unfinished)} of the "` |
| `if not scanned:` | `if not cov.scanned:` |
| `rows = conn.execute("SELECT cr.check_id, ...")` | `rows = cov.by_check` |
| `reasons = _reasons_by_row(conn, engagement_id)` | `reasons = cov.reasons` |
| the `unshipped = sorted(...)` comprehension | `unshipped = coverage_mod.unshipped_classes(config)` |

Keep every comment in `_coverage` exactly as it stands. They record why each
number is shaped the way it is, and the numbers have not changed.

- [ ] **Step 12: Prove the report is byte-identical**

```bash
.venv/bin/pytest tests/test_report.py tests/test_coverage.py -q
.venv/bin/ruff check src tests
awk 'length>88 {print FILENAME": "FNR}' src/hx/coverage.py src/hx/report.py src/hx/run.py
```

Expected: PASS with `tests/test_report.py` **unmodified**, ruff clean, no
long lines. A test in `test_report.py` needing an edit means the extraction
changed the document — stop and report it rather than editing the test.

- [ ] **Step 13: Commit**

```bash
git add src/hx/coverage.py src/hx/report.py tests/test_coverage.py
git commit -m "refactor(coverage): the facts as data, so two renderers cannot disagree"
```

---

## Task 2: Triage — the status writer, the CLI command, and the note in the report

The first code in this tree ever to write `finding_status_event`. The table,
its four triggers and their tests have existed since the store was designed;
`upsert_finding`'s docstring already reserves the seat ("WHAT AN UPSERT MUST
NOT TOUCH: `status`, and `first_seen_run`") and `records.py` names the owners
as "`finding_status_event` and the web app".

This task ships the whole vertical **except** the HTTP route, so triage works
from a terminal before any web code exists.

**The agent-facing guard already exists — verify it, do not rebuild it.**
`tools/spec.py::NEVER_AGENT_FACING` already contains `finding.set_status`,
the registry already refuses it, and a test already asserts that. Step 4
below confirms it; adding a second guard would be a second place the rule
lives.

**Files:**
- Create: `src/hx/triage.py`
- Create: `tests/test_triage.py`
- Create: `tests/test_cli_triage.py`
- Modify: `src/hx/cli.py` (a `triage` command, after `resume`)
- Modify: `src/hx/report.py` (`_findings`' status line, plus a `_status` helper)
- Test: `tests/test_triage.py`, `tests/test_cli_triage.py`, `tests/test_report.py`

**Interfaces:**
- Consumes: `hx.store.db.transaction`, `hx.store.records.new_id`,
  `hx.engagement.now_us`
- Produces, for Tasks 6 and 7:
  - `hx.triage.TARGETS: tuple[str, ...]` — `("confirmed", "false_positive")`
  - `hx.triage.NOTE_REQUIRED: tuple[str, ...]` — `("false_positive",)`
  - `hx.triage.ACTOR: str` — `"human"`
  - `hx.triage.TriageError(Exception)`
  - `hx.triage.StatusChange` — frozen dataclass with `finding_id: str`,
    `from_status: str`, `to_status: str`, `event_id: str | None`,
    `changed: bool`, `ts_us: int`
  - `hx.triage.set_status(conn, *, finding_id, to_status, note=None, now_us=None) -> StatusChange`
  - `hx.triage.history(conn, finding_id) -> tuple`
  - `hx.triage.latest_note(conn, finding_id) -> str | None`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_triage.py`. Note the shape of the two refusal tests: each
asserts the **event count is unchanged**, not merely that an exception was
raised. A test that only asserts the exception passes code that writes the
row and then raises.

```python
"""The only writer of `finding_status_event`, and what it refuses."""
from __future__ import annotations

import pytest

from hx import triage as triage_mod


def _finding(conn, fid="f-1", status="new"):
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES(?,'e-1',?,'Missing HSTS','Low','Firm','check',?,'surface')",
        (fid, f"k-{fid}", status))


def _events(conn, fid="f-1"):
    return conn.execute(
        "SELECT id, from_status, to_status, actor, note FROM"
        " finding_status_event WHERE finding_id=? ORDER BY ts_us, rowid",
        (fid,)).fetchall()


def test_confirming_writes_one_event_and_moves_the_projection(engagement_conn):
    _finding(engagement_conn)
    change = triage_mod.set_status(engagement_conn, finding_id="f-1",
                                   to_status="confirmed")

    assert change.changed is True
    assert change.from_status == "new"
    assert change.to_status == "confirmed"
    events = _events(engagement_conn)
    assert len(events) == 1
    assert events[0][1:5] == ("new", "confirmed", "human", None)
    assert engagement_conn.execute(
        "SELECT status FROM finding WHERE id='f-1'").fetchone()[0] == "confirmed"


def test_the_actor_is_always_human(engagement_conn):
    """Not a parameter. Both callers are humans, and a parameter is a slot a
    future caller fills in wrongly. The enforcement that matters is still
    S8's -- `finding.set_status` is in NEVER_AGENT_FACING, so the agent has
    no path -- and this is the belt beside it."""
    _finding(engagement_conn)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="confirmed")
    assert _events(engagement_conn)[0][3] == "human"


def test_repeating_the_current_status_writes_nothing(engagement_conn):
    """A double-clicked button must not put `confirmed -> confirmed` in an
    audit trail. Idempotent rather than refused: the outcome the caller
    wanted is the outcome they have."""
    _finding(engagement_conn)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="confirmed")
    before = len(_events(engagement_conn))

    change = triage_mod.set_status(engagement_conn, finding_id="f-1",
                                   to_status="confirmed")

    assert change.changed is False
    assert change.event_id is None
    assert len(_events(engagement_conn)) == before


def test_false_positive_without_a_note_is_refused_and_writes_nothing(
        engagement_conn):
    """THE COUNT IS THE ASSERTION. Checking only that it raised would pass
    code that inserts the event and then rejects, which is the failure this
    test exists for."""
    _finding(engagement_conn)
    with pytest.raises(triage_mod.TriageError, match="note is required"):
        triage_mod.set_status(engagement_conn, finding_id="f-1",
                              to_status="false_positive")

    assert _events(engagement_conn) == []
    assert engagement_conn.execute(
        "SELECT status FROM finding WHERE id='f-1'").fetchone()[0] == "new"


def test_a_whitespace_only_note_does_not_count_as_a_note(engagement_conn):
    _finding(engagement_conn)
    with pytest.raises(triage_mod.TriageError, match="note is required"):
        triage_mod.set_status(engagement_conn, finding_id="f-1",
                              to_status="false_positive", note="   \n ")
    assert _events(engagement_conn) == []


def test_dismissing_with_a_note_records_the_reason(engagement_conn):
    _finding(engagement_conn)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="false_positive",
                          note="staging only; header set at the CDN")

    assert _events(engagement_conn)[0][4] == "staging only; header set at the CDN"


def test_a_confirmation_can_be_corrected_and_the_trail_keeps_both(
        engagement_conn):
    """The append-only log is what makes a correctable decision safe: both
    the mistake and the correction stay visible."""
    _finding(engagement_conn)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="confirmed")
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="false_positive", note="misread the diff")

    events = _events(engagement_conn)
    assert [(e[1], e[2]) for e in events] == [
        ("new", "confirmed"), ("confirmed", "false_positive")]


def test_a_status_outside_S11s_two_is_refused(engagement_conn):
    """S11: "finding triage (new -> confirmed | false_positive with a note)".
    `triaged` and `reported` are in the schema's CHECK and unreachable in
    v1, so a caller reaching for one is a caller who has not read S11."""
    _finding(engagement_conn)
    with pytest.raises(triage_mod.TriageError, match="reported"):
        triage_mod.set_status(engagement_conn, finding_id="f-1",
                              to_status="reported", note="in the deliverable")
    assert _events(engagement_conn) == []


def test_an_unknown_finding_is_refused(engagement_conn):
    with pytest.raises(triage_mod.TriageError, match="no finding"):
        triage_mod.set_status(engagement_conn, finding_id="f-nope",
                              to_status="confirmed")


def test_history_is_oldest_first(engagement_conn):
    _finding(engagement_conn)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="confirmed", now_us=10)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="false_positive", note="n", now_us=20)

    rows = triage_mod.history(engagement_conn, "f-1")
    assert [r[1] for r in rows] == ["confirmed", "false_positive"]


def test_latest_note_is_the_most_recent_events(engagement_conn):
    _finding(engagement_conn)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="false_positive", note="first", now_us=10)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="confirmed", now_us=20)
    triage_mod.set_status(engagement_conn, finding_id="f-1",
                          to_status="false_positive", note="second", now_us=30)

    assert triage_mod.latest_note(engagement_conn, "f-1") == "second"


def test_the_trigger_still_refuses_an_agent_confirmation(engagement_conn):
    """Not this module's guard -- the store's. Pinned here because
    `triage.py` is now the thing standing between an agent and this table,
    and the day someone gives `set_status` an `actor` parameter, this is the
    test that says the schema still says no."""
    import sqlite3
    _finding(engagement_conn)
    with pytest.raises(sqlite3.IntegrityError, match="may not set status"):
        engagement_conn.execute(
            "INSERT INTO finding_status_event(id, finding_id, to_status,"
            " actor, ts_us) VALUES('se-x','f-1','confirmed','agent',1)")
```

- [ ] **Step 2: Run them to verify they fail**

```bash
.venv/bin/pytest tests/test_triage.py -q
```

Expected: FAIL, `ModuleNotFoundError: No module named 'hx.triage'`.

- [ ] **Step 3: Create `src/hx/triage.py`**

```python
"""The only writer of `finding_status_event`.

S8: "Creating an engagement and confirming a finding are human acts; they
live in the CLI and the web app." This module is the second half of that
sentence, and it is why `finding.set_status` sits in
`tools.spec.NEVER_AGENT_FACING` rather than in the registry: the agent has
no path here, because the registry is an allowlist and nothing outside it
has a code path at all.

THE EVENT IS THE RECORD; `finding.status` IS A CACHE. `schema.sql` says so
on the column, and the two are written in one transaction so they cannot
disagree. `finding_status_event` is append-only under two triggers, for the
reason `scope_version` is: it is the audit trail of who changed a finding's
status and when, and a status transition that could be silently rewritten
afterwards is not an audit trail.

`actor` IS NOT A PARAMETER. Both callers -- `hx triage` and the web app's
POST route -- are humans by construction, and a parameter here is a slot
some later caller fills in with the wrong thing. The store's own
`trg_agent_cannot_confirm` pair remains the enforcement; this is the belt
beside that brace.
"""
from __future__ import annotations

import dataclasses
import sqlite3

from hx.engagement import now_us as _now_us
from hx.store import db as db_mod
from hx.store.records import new_id

#: S11: "finding triage (`new -> confirmed | false_positive` with a note)".
#: `triaged` and `reported` are in the schema's CHECK constraint and are
#: deliberately unreachable in v1 -- nothing sets `reported`, because nothing
#: yet marks a finding as having gone into a deliverable, and a status
#: reachable only by accident is worse than one that is not reachable.
TARGETS = ("confirmed", "false_positive")

#: Dismissing a finding is the decision a client can challenge and a retest
#: has to honour, so "why did you drop this" is answered at the moment it is
#: dropped. Confirming is the bulk action and carries no friction.
NOTE_REQUIRED = ("false_positive",)

ACTOR = "human"


class TriageError(Exception):
    """A status change this module refuses to make."""


@dataclasses.dataclass(frozen=True)
class StatusChange:
    """What happened, including the case where nothing did.

    `changed` exists so a caller can tell a real transition from an
    idempotent repeat without comparing statuses itself, and `event_id` is
    `None` in exactly that case -- there is no row to point at.
    """

    finding_id: str
    from_status: str
    to_status: str
    event_id: str | None
    changed: bool
    ts_us: int


def set_status(conn: sqlite3.Connection, *, finding_id: str, to_status: str,
               note: str | None = None,
               now_us: int | None = None) -> StatusChange:
    """Record a human triage decision on one finding.

    Refusals happen BEFORE anything is written, and the tests assert the
    event count rather than the exception for that reason: a guard that
    raises after inserting is a guard that does not guard.
    """
    if to_status not in TARGETS:
        raise TriageError(
            f"{to_status!r} is not a triage decision; S11 gives exactly "
            f"{list(TARGETS)} (triaged and reported are unreachable in v1)")

    text = None if note is None else note.strip()
    if to_status in NOTE_REQUIRED and not text:
        raise TriageError(
            f"a note is required to set {to_status}: it is the answer to "
            '"why was this dropped", it goes into the client deliverable, '
            "and a retest has to honour it")

    row = conn.execute("SELECT status FROM finding WHERE id=?",
                       (finding_id,)).fetchone()
    if row is None:
        raise TriageError(f"no finding {finding_id!r} in this engagement")
    current = row[0]
    at = _now_us() if now_us is None else now_us

    if current == to_status:
        # A double-clicked button, or two operators reaching the same
        # conclusion. The outcome the caller asked for is the outcome they
        # have, and `confirmed -> confirmed` in an append-only audit trail is
        # noise in the one place noise costs the most.
        return StatusChange(finding_id=finding_id, from_status=current,
                            to_status=to_status, event_id=None, changed=False,
                            ts_us=at)

    event_id = new_id("se")
    with db_mod.transaction(conn):
        conn.execute(
            "INSERT INTO finding_status_event(id, finding_id, from_status,"
            " to_status, actor, note, ts_us) VALUES(?,?,?,?,?,?,?)",
            (event_id, finding_id, current, to_status, ACTOR, text, at))
        conn.execute("UPDATE finding SET status=? WHERE id=?",
                     (to_status, finding_id))

    return StatusChange(finding_id=finding_id, from_status=current,
                        to_status=to_status, event_id=event_id, changed=True,
                        ts_us=at)


def history(conn: sqlite3.Connection, finding_id: str) -> tuple:
    """Every status event for one finding, oldest first.

    `ts_us, rowid` rather than `ts_us` alone, matching `OperatorHalt`'s own
    ordering: two events inside one microsecond are possible and the later
    INSERT is the later event.
    """
    return tuple(conn.execute(
        "SELECT from_status, to_status, actor, note, ts_us"
        " FROM finding_status_event WHERE finding_id=?"
        " ORDER BY ts_us, rowid", (finding_id,)).fetchall())


def latest_note(conn: sqlite3.Connection, finding_id: str) -> str | None:
    """The note on the most recent status event, or None.

    The report's finding section reads this. A bare `status: false_positive`
    in a client deliverable is S12's rule wearing a different hat: it cannot
    distinguish "we checked and it is not real" from "we did not want to
    write it up".
    """
    row = conn.execute(
        "SELECT note FROM finding_status_event WHERE finding_id=?"
        " ORDER BY ts_us DESC, rowid DESC LIMIT 1", (finding_id,)).fetchone()
    return None if row is None else row[0]
```

- [ ] **Step 4: Run the tests, and confirm the agent guard already exists**

```bash
.venv/bin/pytest tests/test_triage.py -q
command grep -rn 'finding.set_status' src/hx/tools/spec.py tests/test_tools_registry.py
```

Expected: tests PASS, and the grep shows `finding.set_status` already in
`NEVER_AGENT_FACING` with a test asserting the registry refuses it. **Do not
add another guard.** If the grep finds nothing in the tests, say so — that
is a real gap and it changes this step.

- [ ] **Step 5: Commit the writer**

```bash
git add src/hx/triage.py tests/test_triage.py
git commit -m "feat(triage): the first writer of finding_status_event"
```

- [ ] **Step 6: Write the failing CLI test**

Create `tests/test_cli_triage.py`.

```python
"""`hx triage` -- the terminal half of S8's human act."""
from __future__ import annotations

from click.testing import CliRunner

from hx import cli


def _finding(conn, fid="f-1", status="new"):
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES(?,?,?,'Missing HSTS','Low','Firm','check',?,'surface')",
        (fid, conn.execute("SELECT id FROM engagement").fetchone()[0],
         f"k-{fid}", status))


def test_confirming_from_the_cli_moves_the_status(engagement):
    _finding(engagement.db)
    engagement.db.close()

    result = CliRunner().invoke(
        cli.main, ["triage", "f-1", "--status", "confirmed",
                   "--root", str(engagement.root)])

    assert result.exit_code == 0, result.output
    assert "new -> confirmed" in result.output


def test_dismissing_without_a_note_is_refused_at_the_terminal(engagement):
    _finding(engagement.db)
    engagement.db.close()

    result = CliRunner().invoke(
        cli.main, ["triage", "f-1", "--status", "false_positive",
                   "--root", str(engagement.root)])

    assert result.exit_code != 0
    assert "note is required" in result.output


def test_an_unknown_status_is_refused_by_click_before_the_store_is_opened(
        engagement):
    """`click.Choice` over `triage.TARGETS`, so the two vocabularies cannot
    drift and the operator gets the list rather than a traceback."""
    engagement.db.close()

    result = CliRunner().invoke(
        cli.main, ["triage", "f-1", "--status", "reported",
                   "--root", str(engagement.root)])

    assert result.exit_code != 0
    assert "false_positive" in result.output


def test_repeating_a_decision_says_nothing_was_recorded(engagement):
    _finding(engagement.db, status="confirmed")
    engagement.db.close()

    result = CliRunner().invoke(
        cli.main, ["triage", "f-1", "--status", "confirmed",
                   "--root", str(engagement.root)])

    assert result.exit_code == 0, result.output
    assert "nothing recorded" in result.output
```

- [ ] **Step 7: Run it to verify it fails**

```bash
.venv/bin/pytest tests/test_cli_triage.py -q
```

Expected: FAIL, `Error: No such command 'triage'.`

- [ ] **Step 8: Add the `triage` command to `src/hx/cli.py`**

Add the import beside the others (line 20-28 block, alphabetical):

```python
from hx import triage as triage_mod
```

Then the command, immediately **after** the `resume` command and before
`scan`:

```python
@main.command()
@click.argument("finding_id")
@click.option("--status", "to_status", required=True,
              type=click.Choice(triage_mod.TARGETS),
              help="The triage decision. S11 offers exactly these two.")
@click.option("--note", default=None,
              help="Why. REQUIRED for false_positive: it reaches the client "
                   "deliverable, and a retest has to honour it.")
@click.option("--root", type=click.Path(path_type=Path), default=None)
def triage(finding_id, to_status, note, root) -> None:
    """Record a human triage decision on a finding.

    S8 keeps this out of the agent's hands: `finding.set_status` is in
    `NEVER_AGENT_FACING`, so confirming a finding happens here or in the web
    app and nowhere else.
    """
    eng = _open_engagement(root or default_root())
    try:
        change = triage_mod.set_status(eng.db, finding_id=finding_id,
                                       to_status=to_status, note=note)
    except triage_mod.TriageError as exc:
        raise click.ClickException(str(exc)) from exc
    except sqlite3.Error as exc:
        raise click.ClickException(
            f"cannot record the decision at {eng.root}: {exc}") from exc

    if not change.changed:
        click.echo(f"{finding_id}: already {change.to_status}; "
                   "nothing recorded")
        return
    click.echo(f"{finding_id}: {change.from_status} -> {change.to_status}")
    if note and note.strip():
        click.echo(f"  note  {note.strip()}")
```

`note.strip()` rather than a field on `StatusChange`: the dataclass carries
what the store now holds, and the note is the caller's own argument. Adding
it to the return value would mean two places holding one string.

- [ ] **Step 9: Run the CLI tests**

```bash
.venv/bin/pytest tests/test_cli_triage.py tests/test_cli.py -q
```

Expected: PASS, and `tests/test_cli.py` unmodified.

- [ ] **Step 10: Write the failing test for the note in the report**

Append to `tests/test_report.py`:

```python
def test_a_dismissed_findings_reason_reaches_the_report(engagement_conn):
    """S12 pointed at triage. A bare `status: false_positive` in a client
    deliverable cannot distinguish "we checked and it is not real" from "we
    did not want to write it up", and the note is REQUIRED at the moment the
    finding is dropped precisely so that this line can carry it."""
    from hx import triage as triage_mod

    engagement_conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES('f-fp','e-1','k-fp','Missing HSTS','Low','Firm','check',"
        "'new','surface')")
    triage_mod.set_status(engagement_conn, finding_id="f-fp",
                          to_status="false_positive",
                          note="staging only; the CDN sets it in production")

    cfg = config_mod.Config(name="T", client="T", safety_profile="staging",
                            scope_include=["https://app.test/*"])
    out = report_mod.render(engagement_conn, engagement_id="e-1", config=cfg)

    assert "staging only; the CDN sets it in production" in out
    assert "status: false_positive" in out


def test_a_confirmed_finding_with_no_note_still_renders_its_status(
        engagement_conn):
    """The note is optional on `confirmed`, so the status half must not
    depend on one being there."""
    from hx import triage as triage_mod

    engagement_conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES('f-ok','e-1','k-ok','Missing HSTS','Low','Firm','check',"
        "'new','surface')")
    triage_mod.set_status(engagement_conn, finding_id="f-ok",
                          to_status="confirmed")

    cfg = config_mod.Config(name="T", client="T", safety_profile="staging",
                            scope_include=["https://app.test/*"])
    out = report_mod.render(engagement_conn, engagement_id="e-1", config=cfg)

    assert "status: confirmed" in out
```

Check the top of `tests/test_report.py` for how it already imports
`config_mod` and `report_mod`; use the names that file already uses rather
than adding imports.

- [ ] **Step 11: Run it to verify it fails, then implement**

```bash
.venv/bin/pytest tests/test_report.py -k dismissed -q
```

Expected: FAIL — the note is absent from the rendered document.

Add the import to `src/hx/report.py` beside the others:

```python
from hx import triage as triage_mod
```

Add this helper immediately above `_findings`:

```python
def _status(conn, finding_id, status) -> str:
    """The status half of a finding's subtitle, with the human's reason.

    S12 has a sibling nobody wrote down until 2026-09-01: a report that
    cannot distinguish "we checked and it is not real" from "we did not want
    to write it up". A bare `status: false_positive` is exactly that
    ambiguity, and it is why `triage.NOTE_REQUIRED` makes the note
    compulsory on that transition -- the field and its destination are one
    feature, and shipping the first without the second is friction that goes
    nowhere.

    `_flat` and `_redact` for the reason D4 gives: the note is free text a
    human typed, and every rendered free-text value is flattened, not only
    the ones that reach a table.
    """
    if status == "new":
        return ""
    note = triage_mod.latest_note(conn, finding_id)
    if not note:
        return f" · *status: {status}*"
    return f' · *status: {status} — "{_flat(_redact(note))}"*'
```

Then replace the status term in `_findings`' subtitle line:

| Was | Becomes |
|---|---|
| `+ (f" · *status: {status}*" if status != "new" else "")` | `+ _status(conn, fid, status)` |

- [ ] **Step 12: Run the full report suite**

```bash
.venv/bin/pytest tests/test_report.py tests/test_triage.py tests/test_cli_triage.py -q
.venv/bin/ruff check src tests
awk 'length>88 {print FILENAME": "FNR}' src/hx/triage.py src/hx/cli.py src/hx/report.py
```

Expected: PASS, ruff clean, no long lines.

- [ ] **Step 13: Commit**

```bash
git add src/hx/cli.py src/hx/report.py tests/test_cli_triage.py tests/test_report.py
git commit -m "feat(triage): hx triage, and the reason a dismissal reaches the client"
```

---

## Task 3: The app, its guards, and the first two screens

The skeleton and every security invariant in spec §4 that a GET can reach.
Ends with `hx web` serving a list of engagements and an overview of one,
which a hostile page cannot read.

**Why the overview is here and not in a task of its own.** The traversal
test needs a `/e/{name}` route to aim at, and a route that exists only to be
404'd is a placeholder. The engagements list also needs somewhere for its
links to go. Splitting them would leave Task 3 with a dead link and an
untestable allowlist.

**Ruling: Plan A ships no htmx.** The spec's file structure names it, and
Plan A has nothing for it to do — five full-page tables and two ordinary
form POSTs. Vendoring a JavaScript library this plan does not use would add
a supply-chain step and a network fetch for nothing. Plan B vendors it when
SSE and in-body search need it, and widens `script-src` from `'none'` to
`'self'` in the same change, where a reviewer can see it. **Plan A's CSP is
therefore `script-src 'none'`**, which is the stronger policy and the honest
one.

**Files:**
- Modify: `pyproject.toml`
- Create: `src/hx/web/__init__.py`, `src/hx/web/registry.py`,
  `src/hx/web/render.py`, `src/hx/web/app.py`
- Create: `src/hx/web/reads.py`
- Create: `src/hx/web/templates/base.html`, `templates/engagements.html`,
  `templates/overview.html`
- Create: `src/hx/web/static/hx.css`
- Create: `tests/test_web_registry.py`, `tests/test_web_security.py`,
  `tests/test_web_screens.py`
- Modify: `tests/conftest.py` (the `web_base` and `client` fixtures)
- Modify: `src/hx/cli.py` (`hx web`)

**Interfaces:**
- Consumes: `hx.store.db.connect`, `hx.store.db.SCHEMA_VERSION`,
  `hx.store.records.redact_url`
- Produces, for Tasks 4-7:
  - `hx.web.registry.Entry` — frozen dataclass: `name: str`, `path: Path`,
    `engagement_id: str | None`, `client: str | None`, `created_us: int | None`,
    `status: str | None`, `schema_version: int | None`, `problem: str | None`,
    `findings: dict`, `runs: int`
  - `hx.web.registry.scan(base) -> tuple[Entry, ...]`
  - `hx.web.registry.lookup(base, name) -> Entry | None`
  - `hx.web.registry.open_read(entry) -> sqlite3.Connection`
  - `hx.web.render.templates() -> Jinja2Templates`
  - `hx.web.render.TEMPLATES: Path`, `hx.web.render.STATIC: Path`
  - `hx.web.app.create_app(base) -> Starlette`
  - `hx.web.app.ALLOWED_HOSTS: tuple[str, ...]`, `hx.web.app.CSP: str`
  - `hx.web.app.hostname(header) -> str`
  - `hx.web.reads.overview(conn, engagement_id) -> dict`

- [ ] **Step 1: Add the dependencies**

Edit `pyproject.toml`. The `dependencies` line becomes:

```toml
dependencies = [
    "PyYAML>=6.0",
    "click>=8.1",
    # The web app (spec 2026-09-01, master spec S11 as amended). Starlette
    # and NOT FastAPI: measured on 2026-09-01, `fastapi uvicorn jinja2`
    # resolves to 15 packages against `starlette uvicorn jinja2`'s 9, and the
    # six extra include `pydantic-core`, a compiled extension. FastAPI is
    # Starlette plus pydantic validation and OpenAPI generation, and this app
    # is server-rendered Jinja whose entire validated input is a status enum
    # and a note string. S11's own "should not pull hundreds of transitive
    # packages to render a table" is the argument for the smaller closure.
    "starlette>=0.47",
    "jinja2>=3.1",
    "uvicorn>=0.35",
]
```

and the `dev` group gains one entry:

```toml
dev = [
    "pytest>=8.0",
    "ruff>=0.14",
    "mypy>=1.14",
    # `starlette.testclient.TestClient` is httpx-backed. DEV ONLY: nothing in
    # `src/hx` imports it, and the app itself makes no outbound HTTP request
    # of any kind -- S4's invariant is that every byte leaving this machine
    # crosses the JVM, and an HTTP client in the runtime closure is the kind
    # of thing that quietly stops being true.
    "httpx>=0.28",
]
```

Then install:

```bash
uv sync
.venv/bin/python -c "import starlette, jinja2, uvicorn, httpx; print('ok')"
```

- [ ] **Step 2: Write the failing registry tests**

Create `tests/test_web_registry.py`.

```python
"""Which engagements exist, and which names the app will answer to."""
from __future__ import annotations

from hx import config as config_mod
from hx import engagement as eng_mod
from hx.store import db as db_mod
from hx.web import registry as registry_mod


def _make(base, name, client="Acme"):
    cfg = config_mod.Config(name=name, client=client,
                            safety_profile="staging",
                            scope_include=["https://app.test/*"])
    eng = eng_mod.create(base / name, cfg, author="test")
    eng.db.close()
    return eng


def test_an_empty_base_directory_scans_to_nothing(tmp_path):
    assert registry_mod.scan(tmp_path) == ()


def test_a_directory_without_a_database_is_not_an_engagement(tmp_path):
    (tmp_path / "notes").mkdir()
    (tmp_path / "notes" / "scratch.txt").write_text("hello")
    assert registry_mod.scan(tmp_path) == ()


def test_engagements_scan_in_name_order_with_their_client(tmp_path):
    _make(tmp_path, "beta", client="Beta Ltd")
    _make(tmp_path, "alpha", client="Alpha Inc")

    entries = registry_mod.scan(tmp_path)

    assert [e.name for e in entries] == ["alpha", "beta"]
    assert [e.client for e in entries] == ["Alpha Inc", "Beta Ltd"]
    assert all(e.problem is None for e in entries)


def test_a_store_from_another_schema_version_scans_as_a_problem(tmp_path):
    """`engagement.open_` RAISES on a version mismatch, and one stale
    directory must not take down the whole list. The row says which version
    it holds, because "cannot open" without a number is not actionable."""
    _make(tmp_path, "old")
    conn = db_mod.connect(tmp_path / "old" / "hx.db")
    conn.execute(f"PRAGMA user_version={db_mod.SCHEMA_VERSION - 1}")
    conn.close()

    entry = registry_mod.scan(tmp_path)[0]

    assert entry.problem is not None
    assert str(db_mod.SCHEMA_VERSION - 1) in entry.problem
    assert entry.engagement_id is None


def test_lookup_returns_the_named_engagement(tmp_path):
    _make(tmp_path, "alpha")
    assert registry_mod.lookup(tmp_path, "alpha").name == "alpha"


def test_lookup_refuses_a_name_the_scan_did_not_return(tmp_path):
    """THE SCAN IS THE ALLOWLIST. Not a sanitiser over a path join -- an
    allowlist cannot be defeated by an encoding this code did not think of,
    which is the entire argument for one."""
    _make(tmp_path, "alpha")
    for hostile in ("..", "../..", "alpha/../..", "/etc", "", ".",
                    "alpha\x00", "AlPhA"):
        assert registry_mod.lookup(tmp_path, hostile) is None


def test_scan_counts_findings_by_severity(tmp_path):
    eng = _make(tmp_path, "alpha")
    conn = db_mod.connect(tmp_path / "alpha" / "hx.db")
    for n, sev in (("f1", "High"), ("f2", "High"), ("f3", "Low")):
        conn.execute(
            "INSERT INTO finding(id, engagement_id, dedupe_key, title,"
            " severity, confidence, created_by, status, scope_level)"
            " VALUES(?,?,?,'t',?,'Firm','check','new','surface')",
            (n, eng.id, f"k-{n}", sev))
    conn.close()

    entry = registry_mod.lookup(tmp_path, "alpha")

    assert entry.findings == {"High": 2, "Low": 1}
```

- [ ] **Step 3: Run them to verify they fail**

```bash
.venv/bin/pytest tests/test_web_registry.py -q
```

Expected: FAIL, `ModuleNotFoundError: No module named 'hx.web'`.

- [ ] **Step 4: Create the package and the registry**

`src/hx/web/__init__.py` is empty (zero bytes).

`src/hx/web/registry.py`:

```python
"""Which engagements exist under the base directory, and which names are real.

THE SCAN IS THE ALLOWLIST. A URL carries an engagement's DIRECTORY NAME, and
a name this scan did not return is a 404 -- not a sanitised path join, not a
`..` filter, not a `resolve()` compared against a prefix. Every one of those
is a blocklist wearing a helpful expression, and a blocklist fails to the
encoding its author did not think of. This one fails closed by construction:
the only names that resolve are names read off the filesystem.

Every connection opened here is READ-ONLY. `db.connect(readonly=True)` opens
`file:...?mode=ro`, so a write attempt raises `attempt to write a readonly
database` at the SQLite layer rather than depending on this module's
discipline. The store is evidence in a client engagement; a reader that
CANNOT write is a stronger claim than one that merely does not.
"""
from __future__ import annotations

import dataclasses
import sqlite3
from pathlib import Path

from hx.store import db as db_mod


@dataclasses.dataclass(frozen=True)
class Entry:
    """One engagement directory, openable or not.

    `problem` is the honest field. A store written by another schema version
    is a real thing to find on disk -- `engagement.open_` refuses it outright
    -- and the list screen must still render, naming what it found. An entry
    with a `problem` has `engagement_id is None` and no counts; nothing
    downstream may read those without checking.
    """

    name: str
    path: Path
    engagement_id: str | None
    client: str | None
    created_us: int | None
    status: str | None
    schema_version: int | None
    problem: str | None
    findings: dict
    runs: int


def _entry(path: Path) -> Entry:
    name = path.name
    blank = {"name": name, "path": path, "engagement_id": None,
             "client": None, "created_us": None, "status": None,
             "findings": {}, "runs": 0}
    try:
        conn = db_mod.connect(path / "hx.db", readonly=True)
    except sqlite3.Error as exc:
        return Entry(**blank, schema_version=None,
                     problem=f"cannot open the database: {exc}")
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version != db_mod.SCHEMA_VERSION:
            return Entry(
                **blank, schema_version=version,
                problem=f"schema version {version} on disk, this hx expects "
                        f"{db_mod.SCHEMA_VERSION}")
        rows = conn.execute(
            "SELECT id, client, created_us, status FROM engagement").fetchall()
        if len(rows) != 1:
            # The same invariant `engagement.open_` enforces. Guessing which
            # of two rows a screen is about is not an option.
            return Entry(**blank, schema_version=version,
                         problem=f"expected one engagement row, found {len(rows)}")
        row = rows[0]
        findings = {
            r[0]: r[1] for r in conn.execute(
                "SELECT severity, COUNT(*) FROM finding WHERE engagement_id=?"
                " GROUP BY severity", (row[0],)).fetchall()}
        runs = conn.execute(
            "SELECT COUNT(*) FROM run WHERE engagement_id=?",
            (row[0],)).fetchone()[0]
        return Entry(name=name, path=path, engagement_id=row[0],
                     client=row[1], created_us=row[2], status=row[3],
                     schema_version=version, problem=None,
                     findings=findings, runs=runs)
    except sqlite3.Error as exc:
        return Entry(**blank, schema_version=None,
                     problem=f"cannot read the database: {exc}")
    finally:
        conn.close()


def scan(base: Path) -> tuple[Entry, ...]:
    """Every engagement directory under `base`, in name order.

    Per request, not cached: an engagement created in another terminal
    should appear on refresh, and a directory listing is a syscall against a
    handful of entries.

    A directory with no `hx.db` is not an engagement and is skipped in
    silence -- an operator's notes folder living beside their engagements is
    ordinary, not an error.
    """
    base = Path(base)
    try:
        children = sorted(p for p in base.iterdir() if p.is_dir())
    except OSError:
        return ()
    return tuple(_entry(p) for p in children if (p / "hx.db").exists())


def lookup(base: Path, name: str) -> Entry | None:
    """The entry for one directory name, or None if the scan did not find it.

    Goes THROUGH `scan` rather than joining `base / name`, so there is one
    definition of "an engagement this app will answer about". A caller that
    built its own path would be a second definition, and the second one is
    always the one without the allowlist.
    """
    for entry in scan(base):
        if entry.name == name:
            return entry
    return None


def open_read(entry: Entry) -> sqlite3.Connection:
    """A fresh read-only connection to one engagement, for one request.

    FRESH, not cached, and the reason is mechanical: Starlette runs `def`
    endpoints in a threadpool, and `sqlite3` connections default to
    `check_same_thread=True`, so a cached connection raises
    `ProgrammingError` the moment two requests land on different threads.
    Opening a WAL reader is a file open. The app therefore holds no shared
    mutable state at all.
    """
    return db_mod.connect(entry.path / "hx.db", readonly=True)
```

- [ ] **Step 5: Run the registry tests**

```bash
.venv/bin/pytest tests/test_web_registry.py -q
```

Expected: PASS.

- [ ] **Step 6: Add the web fixtures to `tests/conftest.py`**

Append these three. The `base_url` on the client is load-bearing and the
docstring says why — without it every screen test would 421, which is the
allowlist working rather than a bug.

```python
@pytest.fixture
def web_base(tmp_path):
    """A base directory holding two engagements: `alpha` and `beta`.

    Two rather than one, so a screen that reads the wrong store has
    something to be caught by. Both connections are closed: the app opens
    its own read-only connection per request, and a writer left open here
    would hide a WAL visibility bug rather than expose one.
    """
    from hx import config as config_mod
    from hx import engagement as eng_mod

    base = tmp_path / "engagements"
    base.mkdir()
    for name, client in (("alpha", "Alpha Inc"), ("beta", "Beta Ltd")):
        cfg = config_mod.Config(name=name, client=client,
                                safety_profile="staging",
                                scope_include=[f"https://{name}.test/*"])
        eng = eng_mod.create(base / name, cfg, author="test")
        eng.db.close()
    return base


@pytest.fixture
def alpha_db(web_base):
    """A read-write connection to `alpha`, for seeding rows a screen reads."""
    from hx.store import db as db_mod

    conn = db_mod.connect(web_base / "alpha" / "hx.db")
    yield conn
    conn.close()


@pytest.fixture
def client(web_base):
    """A TestClient over `web_base`.

    `base_url` IS THE POINT. TestClient sends `Host: testserver` by default
    and the app's allowlist refuses it with 421 -- correctly, since that is
    the DNS-rebinding defence doing its job. Every screen test would fail
    without this line, and the one test that WANTS the refusal overrides the
    header itself.
    """
    from starlette.testclient import TestClient

    from hx.web.app import create_app

    with TestClient(create_app(web_base),
                    base_url="http://127.0.0.1:8901") as test_client:
        yield test_client
```

- [ ] **Step 7: Write the failing security tests**

Create `tests/test_web_security.py`. **Every test names the mutation that
must turn it red.** A test whose mutation you cannot state is not finished.

```python
"""Spec section 4: what this app can leak, and to whom.

The app renders response bodies captured from a client's application.
Those bodies are attacker-influenced BY DEFINITION -- half the check corpus
exists to find places where attacker input comes back in them -- into a
browser with no authentication in front of it. Each test below names the
mutation that must turn it red; a security test whose failure mode you
cannot state is decoration.
"""
from __future__ import annotations

import sqlite3

import pytest

from hx.web import app as app_mod
from hx.web import registry as registry_mod


def test_the_loopback_host_is_served(client):
    """The control. Without it, a middleware that refused EVERYTHING would
    pass every other test in this file."""
    assert client.get("/").status_code == 200


def test_a_foreign_host_header_is_refused(client):
    """DNS REBINDING. Binding 127.0.0.1 stops remote packets; it does not
    stop a page the operator is browsing from issuing requests to
    127.0.0.1:PORT. A hostile site that resolves its OWN name to 127.0.0.1
    gets same-origin access to every engagement this app can reach. S4 wrote
    the shape of this down for the bridge -- "a loopback port is reachable
    by any local process or browser tab" -- which is why the bridge is a
    Unix socket. A web app cannot be one.

    MUTATION: delete the `hostname(...) not in ALLOWED_HOSTS` branch from
    `_guard`. This test must go red.
    """
    response = client.get("/", headers={"Host": "attacker.example"})
    assert response.status_code == 421
    assert "Alpha Inc" not in response.text


def test_a_host_header_may_carry_a_port(client):
    assert client.get("/", headers={"Host": "127.0.0.1:8901"}).status_code == 200
    assert client.get("/", headers={"Host": "localhost:9"}).status_code == 200


def test_a_host_that_merely_starts_with_an_allowed_name_is_refused(client):
    """`127.0.0.1.attacker.example` is not `127.0.0.1`, and a prefix or
    substring test would say it was.

    MUTATION: change `hostname(...) not in ALLOWED_HOSTS` to
    `not any(h in host for h in ALLOWED_HOSTS)`. This test must go red.
    """
    for hostile in ("127.0.0.1.attacker.example", "localhost.attacker.example",
                    "attacker.example:127.0.0.1"):
        assert client.get("/", headers={"Host": hostile}).status_code == 421


def test_every_response_carries_the_content_security_policy(client):
    """Defence in depth behind autoescape. `default-src 'none'` means a
    rendered `<img src=x onerror=...>` has nothing to load and nothing to
    run, and `script-src 'none'` is honest for Plan A: it ships no
    JavaScript. Plan B widens that to 'self' when it vendors htmx, where a
    reviewer can see it happen.

    MUTATION: delete the `Content-Security-Policy` line from `_guard`.
    """
    csp = client.get("/").headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp


def test_every_response_forbids_content_sniffing(client):
    """MUTATION: delete the `X-Content-Type-Options` line from `_guard`."""
    assert client.get("/").headers["x-content-type-options"] == "nosniff"


def test_a_hostile_client_name_is_escaped_and_not_executed(web_base):
    """THE CORE THREAT, at its cheapest reachable point. `hx new --client`
    takes a string off the command line and the engagements list renders it.
    The same escaping is what stands between a captured response body and
    the operator's browser on the exchange screen.

    MUTATION: pass `autoescape=False` in `render.templates()`. This test
    must go red -- and note that it asserts the RAW form is ABSENT, not
    merely that an escaped form is present, because a page can contain both.
    """
    from hx import config as config_mod
    from hx import engagement as eng_mod
    from starlette.testclient import TestClient

    from hx.web.app import create_app

    payload = "<script>alert(document.domain)</script>"
    cfg = config_mod.Config(name="evil", client=payload,
                            safety_profile="staging",
                            scope_include=["https://app.test/*"])
    eng_mod.create(web_base / "evil", cfg, author="test").db.close()

    with TestClient(create_app(web_base),
                    base_url="http://127.0.0.1:8901") as c:
        body = c.get("/").text

    assert payload not in body
    assert "&lt;script&gt;" in body


def test_the_read_path_cannot_write(web_base):
    """`connect(readonly=True)` opens `file:...?mode=ro`, so a write raises
    at the SQLite layer. This store is EVIDENCE, and `scope_version` and
    `finding_status_event` are append-only because someone may one day
    dispute what it says. A reader that CANNOT write is a stronger claim
    than one that merely does not.

    MUTATION: change `readonly=True` to `readonly=False` in
    `registry.open_read`. This test must go red.
    """
    entry = registry_mod.lookup(web_base, "alpha")
    conn = registry_mod.open_read(entry)
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("UPDATE engagement SET client='changed'")
    finally:
        conn.close()


@pytest.mark.parametrize("name", [
    "..", "%2e%2e", "..%2f..%2fetc", "alpha%2f..%2f..", "beta%00", "ALPHA",
])
def test_a_name_the_scan_did_not_return_is_a_404(client, name):
    """THE REGISTRY SCAN IS THE ALLOWLIST. Not a sanitiser over a path join.

    MUTATION: replace `registry.lookup(base, name)` in the overview handler
    with an entry built from `base / name`. This test must go red.
    """
    assert client.get(f"/e/{name}").status_code == 404


def test_the_hostname_helper_splits_ports_and_brackets():
    """A unit test beside the integration ones, because the parsing is where
    a Host check goes wrong quietly."""
    assert app_mod.hostname("127.0.0.1") == "127.0.0.1"
    assert app_mod.hostname("127.0.0.1:8901") == "127.0.0.1"
    assert app_mod.hostname(" localhost:80 ") == "localhost"
    assert app_mod.hostname("[::1]:8901") == "[::1]"
    assert app_mod.hostname("") == ""
```

- [ ] **Step 8: Run them to verify they fail**

```bash
.venv/bin/pytest tests/test_web_security.py -q
```

Expected: FAIL, `ModuleNotFoundError: No module named 'hx.web.app'`.

- [ ] **Step 9: Create `src/hx/web/render.py`**

```python
"""The Jinja environment, and the filters that must never be forgotten.

AUTOESCAPE IS OURS, NOT A FRAMEWORK DEFAULT. The environment is built here
and handed to `Jinja2Templates(env=...)` rather than letting Starlette
construct one, so that "is autoescape on" is a line in this repository that
a test can pin, instead of a property of whichever Starlette is installed.
It is the single defence between a captured response body and the
operator's browser.

`StrictUndefined` for the same reason: a screen that renders a blank where a
number should be is S12's failure in miniature -- a reader cannot tell
"zero" from "this template asked for a name nobody passed". Every context
value a template reads is passed explicitly, including the ones that are
None.
"""
from __future__ import annotations

import datetime
from pathlib import Path

import jinja2
from starlette.templating import Jinja2Templates

from hx.store import records

TEMPLATES = Path(__file__).parent / "templates"
STATIC = Path(__file__).parent / "static"

#: What a screen shows where a timestamp, count or field is genuinely absent.
#: One spelling, so "we have no value" never reads as "the value is empty".
ABSENT = "—"


def when(us) -> str:
    """A microsecond timestamp as UTC.

    UTC and not local time: a report and a screen read side by side during
    an incident must agree, and the operator's timezone is not part of the
    evidence.
    """
    if us is None:
        return ABSENT
    moment = datetime.datetime.fromtimestamp(us / 1_000_000,
                                             tz=datetime.timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M:%SZ")


def templates() -> Jinja2Templates:
    """The environment every screen renders through."""
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES)),
        autoescape=True,
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    # THE ONE REDACTION RULE, borrowed and not rewritten. `records.redact_url`
    # is already the rule the Java side applies to a request line, character
    # for character, compared over one shared vector file. A second spelling
    # here would be a third rule, and S4 is explicit that Python must never
    # gain a second place that decides any of this.
    #
    # Blob BYTES need no filter: `Redactor.java` runs extension-side before
    # hashing, so what is on disk already carries `{{identity:<id>:authz}}`
    # and `{{observed:set-cookie}}` where credentials were.
    env.filters["redact"] = records.redact_url
    env.filters["when"] = when
    return Jinja2Templates(env=env)
```

- [ ] **Step 10: Create `src/hx/web/reads.py`**

```python
"""Read-only queries, one function per screen.

NOT THE TOOL LAYER, deliberately. `tools/dispatch.py` journals every call --
`journal.record` defaults to `actor="agent"` -- so routing a page view
through it would write one `agent_action` row per view, and the agent
transcript screen would fill with the act of reading it. The audit trail
would stop being able to answer "what did the agent do", which is the
question it exists to answer. The envelopes disagree too: handles and
digests, match-addressed reads and token-budget caps are shaped for a model
with a context window, and a human with a browser has neither constraint.

Every function here takes a connection the caller opened read-only and
returns plain data. None of them render.
"""
from __future__ import annotations

import sqlite3

from hx import coverage as coverage_mod
from hx import run as run_mod


def _run_rows(conn: sqlite3.Connection, engagement_id: str) -> tuple:
    """Every run, newest first, with a display status that tells the truth.

    A run left `running` by a dead harness RENDERS as `error` here and is
    not written back: these connections are read-only, and `run.reap_stale`
    is the writer's job. S5 is explicit -- "an aborted run must never render
    as a clean one, and neither must one that merely STOPPED BEING UPDATED"
    -- and a screen showing `running` for a run the reaper would kill is the
    first thing an operator sees after a crash.
    """
    before = run_mod.stale_before_us()
    out = []
    for row in conn.execute(
            "SELECT id, kind, status, started_us, ended_us, stop_reason,"
            " requests_issued, dropped_total, heartbeat_us, identity_state"
            " FROM run WHERE engagement_id=? ORDER BY started_us DESC, id",
            (engagement_id,)).fetchall():
        stale = run_mod.is_stale(row[2], row[8], row[3], before_us=before)
        out.append({
            "id": row[0], "kind": row[1],
            "status": "error" if stale else row[2],
            "stale": stale,
            "started_us": row[3], "ended_us": row[4],
            "stop_reason": (
                "heartbeat went stale: the harness stopped without closing "
                "this run, so its coverage is incomplete" if stale
                else row[5]),
            "requests_issued": row[6], "dropped_total": row[7],
            "identity_state": row[9],
        })
    return tuple(out)


def overview(conn: sqlite3.Connection, engagement_id: str, config) -> dict:
    """Everything the engagement overview screen shows.

    The coverage figures come from `hx.coverage`, the SAME function
    `report.render` uses, so the screen and the deliverable cannot disagree
    about what was tested. That is not tidiness: a screen with its own
    coverage query loses the denominator, the named untested surfaces and
    the "these numbers are partial" prefix, and shows a reassuring number on
    exactly the engagements where the report shows a warning.
    """
    eng = conn.execute(
        "SELECT id, name, client, created_us, status FROM engagement"
        " WHERE id=?", (engagement_id,)).fetchone()
    scopes = conn.execute(
        "SELECT id, sha256, effective_from_us, author, reason FROM"
        " scope_version WHERE engagement_id=? ORDER BY effective_from_us DESC,"
        " id", (engagement_id,)).fetchall()
    authorizations = conn.execute(
        "SELECT signatory, doc_sha256, valid_from_us, valid_to_us,"
        " scope_sha256 FROM authorization WHERE engagement_id=?"
        " ORDER BY valid_from_us", (engagement_id,)).fetchall()
    severities = {
        row[0]: row[1] for row in conn.execute(
            "SELECT severity, COUNT(*) FROM finding WHERE engagement_id=?"
            " GROUP BY severity", (engagement_id,)).fetchall()}
    statuses = {
        row[0]: row[1] for row in conn.execute(
            "SELECT status, COUNT(*) FROM finding WHERE engagement_id=?"
            " GROUP BY status", (engagement_id,)).fetchall()}
    runs = _run_rows(conn, engagement_id)
    return {
        "engagement": eng,
        "scopes": scopes,
        "authorizations": authorizations,
        "severities": severities,
        "statuses": statuses,
        "runs": runs,
        # S5: a run with drops has coverage numbers that are a FLOOR, not a
        # count. Summed across every run, and rendered beside the figures it
        # qualifies rather than on a page of its own -- putting the caveat
        # somewhere else is how the honest version loses to the reassuring
        # one.
        "dropped_total": sum(r["dropped_total"] or 0 for r in runs),
        "coverage": coverage_mod.facts(conn, engagement_id),
        "unshipped": coverage_mod.unshipped_classes(config),
        "surfaces": conn.execute(
            "SELECT COUNT(*) FROM surface WHERE engagement_id=?",
            (engagement_id,)).fetchone()[0],
        "exchanges": conn.execute(
            "SELECT COUNT(*) FROM exchange x JOIN run r ON r.id = x.run_id"
            " WHERE r.engagement_id=?", (engagement_id,)).fetchone()[0],
    }
```

- [ ] **Step 11: Create `src/hx/web/app.py`**

```python
"""The app: what it serves, and who it refuses to serve it to.

THIS APP SENDS NOTHING. No bridge client, no `Sender`, no socket to the
extension, no outbound HTTP of any kind. S4's invariant -- every byte
leaving this machine crosses one of two points inside the JVM -- is
untouched by everything here, and the security question is not what this
app enforces but what it can LEAK.

Reads open a fresh read-only connection per request and close it. Nothing is
cached between requests, so the app holds no shared mutable state: Starlette
runs `def` endpoints in a threadpool and `sqlite3` connections default to
`check_same_thread=True`, so a cached connection would raise
`ProgrammingError` the moment two requests landed on different threads.
"""
from __future__ import annotations

from pathlib import Path

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from hx import config as config_mod
from hx.web import reads as reads_mod
from hx.web import registry as registry_mod
from hx.web import render as render_mod

#: S11: "v1 binds 127.0.0.1 only". `hx web` has no --host option, so this
#: set is the whole of what an operator can reach the app at -- and, more to
#: the point, the whole of what a DNS-rebinding page cannot.
ALLOWED_HOSTS = ("127.0.0.1", "localhost", "[::1]")

#: `script-src 'none'` is honest for Plan A: it ships no JavaScript at all.
#: Plan B widens it to 'self' in the commit that vendors htmx, where a
#: reviewer sees the widening rather than inheriting it.
CSP = ("default-src 'none'; script-src 'none'; style-src 'self'; "
       "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; "
       "base-uri 'none'")


def hostname(header: str) -> str:
    """The host half of a `Host` header, without its port.

    Bracketed IPv6 first, because `[::1]:8901` split on the first colon is
    `[`. Parsing is where a Host check goes wrong quietly, so it is a named
    function with its own test rather than an expression inside the guard.
    """
    value = header.strip()
    if value.startswith("["):
        end = value.find("]")
        return value if end == -1 else value[:end + 1]
    return value.partition(":")[0]


async def _guard(request, call_next):
    """The Host allowlist, and the headers every response carries.

    THE HOST CHECK IS THE DNS-REBINDING DEFENCE. Binding 127.0.0.1 stops
    remote packets; it does not stop a page the operator is browsing from
    issuing requests to 127.0.0.1:PORT, and a site that resolves its own
    name to 127.0.0.1 would otherwise have same-origin access to every
    engagement on this machine. S4 named the shape of this for the bridge --
    "a loopback port is reachable by any local process or browser tab" --
    and answered it by not being a port at all. A web app has no such
    option.

    421 rather than 403: Misdirected Request is exactly the case, a request
    for an authority this server does not answer for.
    """
    if hostname(request.headers.get("host", "")) not in ALLOWED_HOSTS:
        return PlainTextResponse("this host is not served here",
                                 status_code=421)
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _entry(request):
    """The engagement this request names, or a 404.

    THROUGH `registry.lookup`, which goes through `registry.scan`. A handler
    that built `base / name` itself would be a second definition of "an
    engagement this app answers about", and the second one is always the one
    without the allowlist.
    """
    entry = registry_mod.lookup(request.app.state.base,
                                request.path_params["name"])
    if entry is None or entry.problem is not None:
        raise HTTPException(status_code=404)
    return entry


def index(request):
    entries = registry_mod.scan(request.app.state.base)
    return request.app.state.templates.TemplateResponse(
        request, "engagements.html",
        {"entries": entries, "base": str(request.app.state.base)})


def overview(request):
    entry = _entry(request)
    conn = registry_mod.open_read(entry)
    try:
        config = config_mod.load(entry.path / "config.yaml")
        data = reads_mod.overview(conn, entry.engagement_id, config)
    finally:
        conn.close()
    return request.app.state.templates.TemplateResponse(
        request, "overview.html", {"entry": entry, "config": config, **data})


def create_app(base) -> Starlette:
    app = Starlette(
        routes=[
            Route("/", index),
            Route("/e/{name}", overview),
            Mount("/static",
                  StaticFiles(directory=str(render_mod.STATIC)),
                  name="static"),
        ],
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=_guard)],
    )
    app.state.base = Path(base)
    app.state.templates = render_mod.templates()
    return app
```

- [ ] **Step 12: Create the templates and the stylesheet**

`src/hx/web/templates/base.html`:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{% block title %}hx{% endblock %} · hx</title>
<link rel="stylesheet" href="/static/hx.css">
</head>
<body>
<header>
  <a class="home" href="/">hx</a>
  {% block crumb %}{% endblock %}
</header>
<main>
{% block content %}{% endblock %}
</main>
</body>
</html>
```

`src/hx/web/templates/engagements.html`:

```html
{% extends "base.html" %}
{% block title %}Engagements{% endblock %}
{% block content %}
<h1>Engagements</h1>
<p class="muted">{{ base }}</p>
{% if not entries %}
<p>No engagement here yet. <code>hx new NAME --client CLIENT --scope URL</code> creates one.</p>
{% else %}
<table>
<thead><tr>
  <th>Engagement</th><th>Client</th><th>Status</th><th>Created</th>
  <th class="num">Runs</th><th>Findings</th>
</tr></thead>
<tbody>
{% for e in entries %}
<tr>
{% if e.problem %}
  <td>{{ e.name }}</td>
  <td colspan="5" class="problem">unreadable — {{ e.problem }}</td>
{% else %}
  <td><a href="/e/{{ e.name }}">{{ e.name }}</a></td>
  <td>{{ e.client }}</td>
  <td>{{ e.status }}</td>
  <td>{{ e.created_us | when }}</td>
  <td class="num">{{ e.runs }}</td>
  <td>
  {% for sev, n in e.findings.items() %}
    <span class="sev sev-{{ sev | lower }}">{{ sev }} {{ n }}</span>
  {% else %}
    —
  {% endfor %}
  </td>
{% endif %}
</tr>
{% endfor %}
</tbody>
</table>
{% endif %}
{% endblock %}
```

`src/hx/web/templates/overview.html`:

```html
{% extends "base.html" %}
{% block title %}{{ entry.name }}{% endblock %}
{% block crumb %}<span class="crumb">{{ entry.name }}</span>{% endblock %}
{% block content %}
<h1>{{ entry.name }}</h1>
<p class="muted">{{ entry.client }} · created {{ entry.created_us | when }} · {{ entry.status }}</p>

{% if dropped_total %}
<p class="warn"><strong>{{ dropped_total }} exchange(s) were dropped.</strong>
Every count on this page is a <strong>floor, not a total</strong> — the
extension could not hand over every exchange it saw.</p>
{% endif %}

<h2>Scope of record</h2>
<table>
<thead><tr><th>Effective</th><th>sha256</th><th>Author</th><th>Reason</th></tr></thead>
<tbody>
{% for s in scopes %}
<tr><td>{{ s[2] | when }}</td><td class="hash">{{ s[1] }}</td><td>{{ s[3] }}</td><td>{{ s[4] }}</td></tr>
{% endfor %}
</tbody>
</table>
<ul class="scope">
{% for pattern in config.scope_include %}<li class="include">{{ pattern | redact }}</li>{% endfor %}
{% for pattern in config.scope_exclude %}<li class="exclude">{{ pattern | redact }}</li>{% endfor %}
</ul>

<h2>Authorisation</h2>
{% if authorizations %}
<table>
<thead><tr><th>Signatory</th><th>Document</th><th>From</th><th>To</th></tr></thead>
<tbody>
{% for a in authorizations %}
<tr><td>{{ a[0] }}</td><td class="hash">{{ a[1] }}</td><td>{{ a[2] | when }}</td><td>{{ a[3] | when }}</td></tr>
{% endfor %}
</tbody>
</table>
{% else %}
<p class="warn">No authorisation record. Nothing in hx writes this table yet,
so its absence says nothing about whether the work was authorised — it says
this store has no record of it.</p>
{% endif %}

<h2>Runs</h2>
{% if not runs %}
<p>No run has been opened for this engagement.</p>
{% else %}
<table>
<thead><tr>
  <th>Kind</th><th>Status</th><th>Started</th><th>Ended</th>
  <th class="num">Issued</th><th class="num">Dropped</th><th>Why it stopped</th>
</tr></thead>
<tbody>
{% for r in runs %}
<tr class="{{ 'stale' if r.stale else '' }}">
  <td>{{ r.kind }}</td>
  <td class="status status-{{ r.status }}">{{ r.status }}</td>
  <td>{{ r.started_us | when }}</td>
  <td>{{ r.ended_us | when }}</td>
  <td class="num">{{ r.requests_issued }}</td>
  <td class="num">{{ r.dropped_total }}</td>
  <td>{{ r.stop_reason or "—" }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% endif %}

<h2>Coverage</h2>
{% if coverage.unfinished %}
<p class="warn"><strong>These numbers are partial.</strong>
{{ coverage.unfinished | length }} of the runs behind them did not finish, so
a check that never opened for a surface may simply be one the run never got to.</p>
{% endif %}
{% if not coverage.captured %}
<p>No surface was captured, so there is nothing here for a check to have covered.</p>
{% else %}
<p>{{ coverage.captured }} surface(s) captured.
<strong>{{ coverage.captured - (coverage.untested | length) }}</strong> had at
least one check return a verdict; <strong>{{ coverage.untested | length }}</strong> had none.</p>
{% endif %}
{% if not coverage.scanned %}
<p class="warn">This engagement has <strong>not been scanned</strong>. No check
has run against any surface, so nothing here should be read as tested.</p>
{% else %}
<table>
<thead><tr><th>Check</th><th>Verdict</th><th class="num">Surfaces</th></tr></thead>
<tbody>
{% for check_id, verdict, n in coverage.by_check %}
<tr><td><code>{{ check_id }}</code></td><td>{{ verdict }}</td><td class="num">{{ n }}</td></tr>
{% endfor %}
</tbody>
</table>
{% endif %}
{% for klass in unshipped %}
<p class="warn"><code>{{ klass }}</code> is enabled in this engagement's config,
but this build ships no checks in that class — nothing above is coverage for it.</p>
{% endfor %}
{% if coverage.untested %}
<h3>Never tested</h3>
<p>These {{ coverage.untested | length }} surface(s) were captured and no check
ever returned a verdict for them. A surface named here was <strong>never
reached</strong>, which is not the same as clean.</p>
<ul class="untested">
{% for method, template in coverage.untested %}<li><code>{{ method }} {{ template }}</code></li>{% endfor %}
</ul>
{% endif %}

<h2>Findings</h2>
<p>
{% for sev, n in severities.items() %}<span class="sev sev-{{ sev | lower }}">{{ sev }} {{ n }}</span> {% else %}None recorded.{% endfor %}
</p>
<p class="muted">{{ surfaces }} surface(s) · {{ exchanges }} exchange(s)</p>
{% endblock %}
```

`src/hx/web/static/hx.css`: any legible stylesheet. It must define at least
`.warn`, `.problem`, `.muted`, `.num`, `.hash`, `.sev`, `.status`, `.stale`
and `.crumb`, since the templates use them. Keep it under 100 lines; there
is no test on appearance and none is wanted.

- [ ] **Step 13: Add `hx web` to `src/hx/cli.py`**

```python
@main.command()
@click.option("--base", "base", type=click.Path(path_type=Path), default=None,
              help="Directory holding engagements. Defaults to the same "
                   "place `hx new` writes them.")
@click.option("--port", type=int, default=8901, show_default=True)
def web(base, port) -> None:
    """Serve the read-only web app on 127.0.0.1.

    THERE IS NO --host OPTION. S11: "v1 binds 127.0.0.1 only... when it is
    bound [wider], a per-install bearer token lands BEFORE the first write
    endpoint." Neither ships here, so the way to guarantee the binding is to
    give the operator no flag to get it wrong -- the same reasoning the
    integration suite's TargetServer uses when it refuses any address
    outside 127.0.0.0/8.

    `--base` is the engagements PARENT directory, matching what `hx new
    --root` means. Every other command's `--root` is one engagement's own
    directory; that inconsistency predates this command and is recorded in
    docs/DECISIONS.md rather than fixed by renaming six merged flags.
    """
    import uvicorn

    from hx.web.app import create_app

    root = base or default_root()
    click.echo(f"serving {root} at http://127.0.0.1:{port}")
    click.echo("read-only except for finding triage and STOP; "
               "`hx resume` is the only way to lift a halt")
    uvicorn.run(create_app(root), host="127.0.0.1", port=port,
                # The access log carries request paths, and a path here can
                # carry a search string an operator typed. Nothing about a
                # client engagement belongs in a terminal scrollback by
                # default.
                access_log=False, log_level="warning")
```

The `import uvicorn` is deliberately inside the function: `hx tool`, `hx
scan` and `hx mcp` should not pay for an ASGI server's import at startup.

- [ ] **Step 14: Write the failing screen tests**

Create `tests/test_web_screens.py`. Each assertion is something that
changes if the query is wrong — never a bare `status_code == 200`, which is
the vacuous shape this repo has shipped before.

```python
"""Each screen shows the right data, not merely a 200."""
from __future__ import annotations


def test_the_index_lists_both_engagements_with_their_clients(client):
    body = client.get("/").text
    assert "alpha" in body and "Alpha Inc" in body
    assert "beta" in body and "Beta Ltd" in body


def test_the_overview_names_the_engagement_and_its_scope_hash(client, alpha_db):
    sha = alpha_db.execute(
        "SELECT sha256 FROM scope_version").fetchone()[0]
    body = client.get("/e/alpha").text
    assert "Alpha Inc" in body
    assert sha in body


def test_an_unscanned_engagement_says_so_rather_than_showing_a_clean_bill(
        client):
    """S12. Silence where coverage should be reads as coverage."""
    body = client.get("/e/alpha").text
    assert "not been scanned" in body


def test_a_captured_but_untested_surface_is_named_not_just_counted(
        client, alpha_db):
    """The half of S12 a count cannot carry: "did you test the password
    reset flow?" needs the surface NAMED."""
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES('s1',?,'POST','https','alpha.test',443,'/password/reset',"
        "'proxy',2)", (eid,))

    body = client.get("/e/alpha").text

    assert "/password/reset" in body
    assert "Never tested" in body


def test_a_run_with_drops_says_its_numbers_are_a_floor(client, alpha_db):
    """S5: a run with drops has coverage numbers that are a FLOOR, not a
    count, and the warning sits beside the figures it qualifies."""
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status, requests_issued, dropped_total)"
        " VALUES('r1',?,'scan','staging',1,'completed',10,3)", (eid,))

    body = client.get("/e/alpha").text

    assert "floor" in body.lower()
    assert "3 exchange(s) were dropped" in body


def test_a_running_run_with_a_dead_heartbeat_renders_as_error(
        client, alpha_db):
    """S5 again: "an aborted run must never render as a clean one, and
    neither must one that merely STOPPED BEING UPDATED". The screen cannot
    reap it -- its connections are read-only -- so it must render the truth
    without writing it.

    MUTATION: make `reads._run_rows` return `row[2]` unconditionally. This
    test must go red.
    """
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status, heartbeat_us, requests_issued, dropped_total)"
        " VALUES('r1',?,'scan','staging',1,'running',1,0,0)", (eid,))

    body = client.get("/e/alpha").text

    assert "status-error" in body
    assert "status-running" not in body


def test_the_overview_reads_the_engagement_the_url_names(client, alpha_db):
    """Two engagements exist; `beta` must not show `alpha`'s client."""
    assert "Alpha Inc" not in client.get("/e/beta").text
    assert "Beta Ltd" in client.get("/e/beta").text


def test_the_coverage_figures_match_what_the_report_computes(
        client, alpha_db, web_base):
    """THE TEST THE EXTRACTION EXISTS FOR. One store, two renderers, the
    same numbers. A second coverage query would drift, and the drift would
    show a reassuring figure on exactly the engagements the report warns
    about."""
    from hx import config as config_mod
    from hx import coverage as coverage_mod

    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES('s1',?,'GET','https','alpha.test',443,'/a','proxy',2)", (eid,))
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status, requests_issued, dropped_total)"
        " VALUES('r1',?,'scan','staging',1,'completed',1,0)", (eid,))
    alpha_db.execute(
        "INSERT INTO check_run(id, run_id, surface_id, check_id,"
        " check_version, verdict) VALUES('c1','r1','s1','missing-hsts','1',"
        "'clean')")

    cov = coverage_mod.facts(alpha_db, eid)
    config_mod.load(web_base / "alpha" / "config.yaml")
    body = client.get("/e/alpha").text

    assert cov.captured == 1
    assert f"{cov.captured} surface(s) captured" in body
    assert "missing-hsts" in body
    assert "Never tested" not in body
```

- [ ] **Step 15: Run everything and check the gate**

```bash
.venv/bin/pytest tests/test_web_registry.py tests/test_web_security.py \
    tests/test_web_screens.py -q
.venv/bin/pytest -q
.venv/bin/ruff check src tests
awk 'length>88 {print FILENAME": "FNR}' src/hx/web/*.py src/hx/cli.py
```

Expected: all PASS, ruff clean, no long lines, and the full suite still
green with the integration count unchanged at 46 deselected.

- [ ] **Step 16: Verify the app actually starts**

```bash
timeout 5 .venv/bin/hx web --base /tmp/nonexistent-engagements --port 8917 &
sleep 2 && curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8917/
curl -sS -o /dev/null -w '%{http_code}\n' -H 'Host: evil.example' \
    http://127.0.0.1:8917/
wait
```

Expected: `200` then `421`. A `TestClient` exercises the app; this proves
uvicorn serves it.

- [ ] **Step 17: Commit**

```bash
git add pyproject.toml uv.lock src/hx/web tests/conftest.py \
    tests/test_web_registry.py tests/test_web_security.py \
    tests/test_web_screens.py src/hx/cli.py
git commit -m "feat(web): the app, its guards, and an engagement you can read"
```

---

## Task 4: The surface and findings screens

Two competent tables, in §11's own words. The one judgement in them is what
happens to an unknown filter value: it is **refused**, not ignored. A screen
that silently drops a filter shows more rows than the operator asked for
while looking like it obeyed, and "I filtered to confirmed and saw none" is
then a false statement about the data.

**Files:**
- Modify: `src/hx/web/reads.py` (`SEVERITIES`, `STATUSES`, `surfaces`, `findings`)
- Modify: `src/hx/web/app.py` (two routes)
- Create: `src/hx/web/templates/surfaces.html`, `templates/findings.html`
- Modify: `src/hx/web/templates/overview.html` (links to both)
- Test: `tests/test_web_screens.py`

**Interfaces:**
- Consumes: `hx.coverage.ANSWERED`
- Produces, for Tasks 5-6:
  - `hx.web.reads.SEVERITIES: tuple[str, ...]`
  - `hx.web.reads.STATUSES: tuple[str, ...]`
  - `hx.web.reads.surfaces(conn, engagement_id) -> tuple`
  - `hx.web.reads.findings(conn, engagement_id, *, severity=None, status=None) -> tuple`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_web_screens.py`.

```python
def _surface(conn, eid, sid="s1", method="GET", template="/a"):
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES(?,?,?,'https','alpha.test',443,?,'proxy',2)",
        (sid, eid, method, template))


def _finding(conn, eid, fid="f1", severity="High", status="new",
             title="Reflected input", surface_id=None):
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level, surface_id,"
        " check_id) VALUES(?,?,?,?,?,'Firm','check',?,'surface',?,'refl')",
        (fid, eid, f"k-{fid}", title, severity, status, surface_id))


def test_the_surface_screen_names_each_surface_and_how_it_was_found(
        client, alpha_db):
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _surface(alpha_db, eid, template="/order/{id}")

    body = client.get("/e/alpha/surfaces").text

    assert "/order/{id}" in body
    assert "proxy" in body


def test_a_surface_whose_only_check_row_is_skipped_shows_no_answers(
        client, alpha_db):
    """`answered` counts only verdicts in `coverage.ANSWERED`. A `skipped`
    row records a GAP -- the budget cut the scan off before it -- and
    counting it would make the column say a check ran when none did.

    MUTATION: drop the `verdict IN (...)` clause from `reads.surfaces`.
    This test must go red.
    """
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _surface(alpha_db, eid)
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r1',?,'scan','staging',1,'completed')", (eid,))
    alpha_db.execute(
        "INSERT INTO check_run(id, run_id, surface_id, check_id,"
        " check_version, verdict) VALUES('c1','r1','s1','x','1','skipped')")

    from hx.web import reads as reads_mod
    from hx.web import registry as registry_mod

    conn = registry_mod.open_read(registry_mod.lookup(
        client.app.state.base, "alpha"))
    try:
        assert reads_mod.surfaces(conn, eid)[0]["answered"] == 0
    finally:
        conn.close()


def test_the_findings_screen_orders_by_severity(client, alpha_db):
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _finding(alpha_db, eid, fid="f-low", severity="Low", title="Low one")
    _finding(alpha_db, eid, fid="f-crit", severity="Critical",
             title="Critical one")

    body = client.get("/e/alpha/findings").text

    assert body.index("Critical one") < body.index("Low one")


def test_filtering_by_status_hides_the_others(client, alpha_db):
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _finding(alpha_db, eid, fid="f-new", status="new", title="Still new")
    _finding(alpha_db, eid, fid="f-fp", status="false_positive",
             title="Already dismissed")

    body = client.get("/e/alpha/findings?status=false_positive").text

    assert "Already dismissed" in body
    assert "Still new" not in body


def test_an_unknown_filter_value_is_refused_rather_than_ignored(client):
    """A screen that silently drops a filter shows MORE than was asked for
    while looking obedient, and "I filtered to confirmed and saw none"
    becomes a false statement about the data.

    MUTATION: make `findings` ignore an unrecognised value instead of
    raising. This test must go red.
    """
    response = client.get("/e/alpha/findings?status=definitely_fine")
    assert response.status_code == 400
    assert "false_positive" in response.text


def test_the_findings_screen_shows_the_current_status(client, alpha_db):
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _finding(alpha_db, eid, fid="f1", status="confirmed")

    assert "confirmed" in client.get("/e/alpha/findings").text
```

- [ ] **Step 2: Run them to verify they fail**

```bash
.venv/bin/pytest tests/test_web_screens.py -q -k "surface or findings or filter"
```

Expected: FAIL with 404s from the two missing routes.

- [ ] **Step 3: Add the queries to `src/hx/web/reads.py`**

Add the import and both vocabularies below the existing imports:

```python
#: `finding.severity`'s CHECK constraint, in the order a reader wants them.
#: Copied deliberately rather than derived: the column's vocabulary is
#: closed, and a filter that accepted something the column cannot hold would
#: silently return nothing and look like a clean result.
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

#: `finding.status`'s CHECK constraint. WIDER than `triage.TARGETS`, and
#: deliberately: triage may only WRITE two of these, but a store can hold
#: any of the five and a filter that could not name them would hide rows.
STATUSES = ("new", "triaged", "confirmed", "false_positive", "reported")


class FilterError(Exception):
    """A filter value outside the column's closed vocabulary."""
```

Then both functions:

```python
def surfaces(conn: sqlite3.Connection, engagement_id: str) -> tuple:
    """Every captured surface, with how much was done to it.

    `answered` counts DISTINCT checks whose verdict is in
    `coverage.ANSWERED` -- the same definition the report and the overview
    use. A `pending` or `skipped` row records a gap, and a column that
    counted them would say a check ran when none did, which is S12's failure
    at the level of a single table cell.
    """
    marks = ",".join("?" for _ in coverage_mod.ANSWERED)
    rows = conn.execute(
        "SELECT s.id, s.method, s.scheme, s.host, s.port, s.path_template,"
        " s.query_key_set, s.kind, s.discovered_by,"
        " (SELECT COUNT(*) FROM exchange x WHERE x.surface_id = s.id),"
        f" (SELECT COUNT(DISTINCT cr.check_id) FROM check_run cr"
        f"  WHERE cr.surface_id = s.id AND cr.verdict IN ({marks}))"
        " FROM surface s WHERE s.engagement_id=?"
        " ORDER BY s.path_template, s.method, s.id",
        (*coverage_mod.ANSWERED, engagement_id)).fetchall()
    return tuple({
        "id": r[0], "method": r[1], "scheme": r[2], "host": r[3],
        "port": r[4], "path_template": r[5], "query_key_set": r[6],
        "kind": r[7], "discovered_by": r[8], "exchanges": r[9],
        "answered": r[10],
    } for r in rows)


def findings(conn: sqlite3.Connection, engagement_id: str, *,
             severity: str | None = None,
             status: str | None = None) -> tuple:
    """Findings, most severe first, optionally filtered.

    An unrecognised filter value RAISES rather than being ignored. A screen
    that quietly drops a filter shows more rows than were asked for while
    looking as though it obeyed, and the operator's conclusion -- "I
    filtered to confirmed and there were none" -- becomes a false statement
    about their own data.
    """
    if severity is not None and severity not in SEVERITIES:
        raise FilterError(
            f"{severity!r} is not a severity; this store holds "
            f"{list(SEVERITIES)}")
    if status is not None and status not in STATUSES:
        raise FilterError(
            f"{status!r} is not a status; this store holds {list(STATUSES)}")

    where = ["f.engagement_id=?"]
    args: list = [engagement_id]
    if severity is not None:
        where.append("f.severity=?")
        args.append(severity)
    if status is not None:
        where.append("f.status=?")
        args.append(status)

    order = " ".join(
        f"WHEN '{name}' THEN {n}" for n, name in enumerate(SEVERITIES))
    rows = conn.execute(
        "SELECT f.id, f.title, f.severity, f.confidence, f.status,"
        " f.check_id, f.host, s.method, s.path_template"
        " FROM finding f LEFT JOIN surface s ON s.id = f.surface_id"
        " WHERE " + " AND ".join(where) +
        f" ORDER BY CASE f.severity {order} ELSE 99 END, f.title, f.id",
        args).fetchall()
    return tuple({
        "id": r[0], "title": r[1], "severity": r[2], "confidence": r[3],
        "status": r[4], "check_id": r[5], "host": r[6],
        "method": r[7], "path_template": r[8],
    } for r in rows)
```

The `order` string is built from `SEVERITIES` by interpolation and not by
parameters, because SQLite will not take a bound parameter in a `CASE`
label. It is safe for exactly one reason and it is worth being explicit:
`SEVERITIES` is a module constant in this file, never a caller's input.

Add `from hx import coverage as coverage_mod` to the imports if Task 3 did
not already (it did — `overview` uses it).

- [ ] **Step 4: Add the routes to `src/hx/web/app.py`**

```python
def surfaces(request):
    entry = _entry(request)
    conn = registry_mod.open_read(entry)
    try:
        rows = reads_mod.surfaces(conn, entry.engagement_id)
    finally:
        conn.close()
    return request.app.state.templates.TemplateResponse(
        request, "surfaces.html", {"entry": entry, "surfaces": rows})


def findings(request):
    entry = _entry(request)
    conn = registry_mod.open_read(entry)
    try:
        rows = reads_mod.findings(
            conn, entry.engagement_id,
            severity=request.query_params.get("severity"),
            status=request.query_params.get("status"))
    except reads_mod.FilterError as exc:
        return PlainTextResponse(str(exc), status_code=400)
    finally:
        conn.close()
    return request.app.state.templates.TemplateResponse(
        request, "findings.html", {
            "entry": entry, "findings": rows,
            "severities": reads_mod.SEVERITIES,
            "statuses": reads_mod.STATUSES,
            "severity": request.query_params.get("severity"),
            "status": request.query_params.get("status"),
        })
```

and both routes, after `/e/{name}`:

```python
            Route("/e/{name}/surfaces", surfaces),
            Route("/e/{name}/findings", findings),
```

- [ ] **Step 5: Create the two templates**

`src/hx/web/templates/surfaces.html`:

```html
{% extends "base.html" %}
{% block title %}{{ entry.name }} surfaces{% endblock %}
{% block crumb %}<span class="crumb"><a href="/e/{{ entry.name }}">{{ entry.name }}</a> · surfaces</span>{% endblock %}
{% block content %}
<h1>Surface</h1>
{% if not surfaces %}
<p>Nothing captured yet. Surfaces arrive through the proxy — browse the
target through Burp, or run <code>hx capture start</code>.</p>
{% else %}
<p class="muted">{{ surfaces | length }} surface(s). A surface is the
<em>template</em>, not the URL: <code>/order/1</code> and
<code>/order/9999</code> are one row.</p>
<table>
<thead><tr>
  <th>Method</th><th>Path template</th><th>Host</th><th>Query keys</th>
  <th>Kind</th><th>Found by</th><th class="num">Exchanges</th>
  <th class="num">Checks answered</th>
</tr></thead>
<tbody>
{% for s in surfaces %}
<tr>
  <td>{{ s.method }}</td>
  <td><code>{{ s.path_template }}</code></td>
  <td>{{ s.scheme }}://{{ s.host }}:{{ s.port }}</td>
  <td>{{ s.query_key_set or "—" }}</td>
  <td>{{ s.kind }}</td>
  <td>{{ s.discovered_by }}</td>
  <td class="num">{{ s.exchanges }}</td>
  <td class="num {{ 'warn-cell' if not s.answered else '' }}">{{ s.answered }}</td>
</tr>
{% endfor %}
</tbody>
</table>
<p class="muted">A zero in the last column means <strong>no check ever
returned a verdict</strong> for that surface — never reached, which is not
the same as clean.</p>
{% endif %}
{% endblock %}
```

`src/hx/web/templates/findings.html`:

```html
{% extends "base.html" %}
{% block title %}{{ entry.name }} findings{% endblock %}
{% block crumb %}<span class="crumb"><a href="/e/{{ entry.name }}">{{ entry.name }}</a> · findings</span>{% endblock %}
{% block content %}
<h1>Findings</h1>
<form method="get" class="filters">
  <label>Severity
    <select name="severity">
      <option value="">any</option>
      {% for s in severities %}
      <option value="{{ s }}" {{ 'selected' if s == severity else '' }}>{{ s }}</option>
      {% endfor %}
    </select>
  </label>
  <label>Status
    <select name="status">
      <option value="">any</option>
      {% for s in statuses %}
      <option value="{{ s }}" {{ 'selected' if s == status else '' }}>{{ s }}</option>
      {% endfor %}
    </select>
  </label>
  <button type="submit">Filter</button>
  <a href="/e/{{ entry.name }}/findings">clear</a>
</form>
{% if not findings %}
<p>No finding matches.{% if severity or status %} The filter is on; <a href="/e/{{ entry.name }}/findings">clear it</a> to see everything.{% endif %}</p>
{% else %}
<table>
<thead><tr>
  <th>Severity</th><th>Title</th><th>Where</th><th>Check</th>
  <th>Confidence</th><th>Status</th>
</tr></thead>
<tbody>
{% for f in findings %}
<tr>
  <td><span class="sev sev-{{ f.severity | lower }}">{{ f.severity }}</span></td>
  <td><a href="/e/{{ entry.name }}/findings/{{ f.id }}">{{ f.title }}</a></td>
  <td>{% if f.path_template %}<code>{{ f.method }} {{ f.path_template }}</code>{% else %}{{ f.host or "—" }}{% endif %}</td>
  <td><code>{{ f.check_id or "—" }}</code></td>
  <td>{{ f.confidence }}</td>
  <td class="status status-{{ f.status }}">{{ f.status }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% endif %}
{% endblock %}
```

The finding-detail link lands in Task 5. It 404s until then, which is
visible in a browser and is why Task 5 follows immediately.

- [ ] **Step 6: Link both screens from the overview**

In `overview.html`, under the `<h1>`, add:

```html
<nav class="screens">
  <a href="/e/{{ entry.name }}/surfaces">Surface</a>
  <a href="/e/{{ entry.name }}/findings">Findings</a>
</nav>
```

- [ ] **Step 7: Run the tests and the gate**

```bash
.venv/bin/pytest tests/test_web_screens.py -q
.venv/bin/pytest -q
.venv/bin/ruff check src tests
awk 'length>88 {print FILENAME": "FNR}' src/hx/web/reads.py src/hx/web/app.py
```

Expected: all PASS, ruff clean, no long lines.

- [ ] **Step 8: Commit**

```bash
git add src/hx/web tests/test_web_screens.py
git commit -m "feat(web): the surface and findings screens, and a filter that refuses"
```

---

## Task 5: Finding detail, the evidence chain, and a plain exchange view

The screen triage happens from, and the one it depends on. §8 puts triage in
v1 because it has no substitute — but triage has a prerequisite: you cannot
decide whether a finding is real without looking at the exchange that
produced it. This task ships the looking; Task 6 ships the deciding.

**The exchange view here is deliberately plain** — an escaped `<pre>` of
request and response, plus metadata. Plan B upgrades this same route into
§11's *"one screen worth real effort"*: highlighting, in-body search, hex
toggle, and the side-by-side `replay_as` diff.

**Files:**
- Modify: `src/hx/web/reads.py` (`finding_detail`, `evidence`, `observations`, `exchange`)
- Modify: `src/hx/web/app.py` (two routes)
- Create: `src/hx/web/templates/finding.html`, `templates/exchange.html`
- Create: `tests/test_credentials_never_reach_the_screen.py`
- Test: `tests/test_web_screens.py`

**Interfaces:**
- Consumes: `hx.triage.history`, `hx.store.blobs.BlobStore`,
  `hx.store.blobs.CorruptBlob`
- Produces, for Task 6:
  - `hx.web.reads.finding_detail(conn, finding_id) -> dict | None`
  - `hx.web.reads.evidence(conn, finding_id) -> tuple`
  - `hx.web.reads.observations(conn, finding_id) -> tuple`
  - `hx.web.reads.exchange(conn, blobs, exchange_id) -> dict | None`
  - `hx.web.reads.TEXT: str` — `"latin-1"`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_web_screens.py`:

```python
def test_the_finding_detail_shows_its_evidence_chain(client, alpha_db):
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _finding(alpha_db, eid, fid="f1")
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r1',?,'scan','staging',1,'completed')", (eid,))
    alpha_db.execute(
        "INSERT INTO exchange(id, run_id, via, outcome, sent_us, method, url,"
        " status) VALUES('x1','r1','send','ok',1,'GET',"
        "'https://alpha.test/search?q=1',200)")
    alpha_db.execute(
        "INSERT INTO evidence(id, finding_id, seq, role, kind, exchange_id,"
        " note, captured_us) VALUES('ev1','f1',1,'proof','exchange','x1',"
        "'the payload came back verbatim',1)")

    body = client.get("/e/alpha/findings/f1").text

    assert "the payload came back verbatim" in body
    assert "x1" in body


def test_the_finding_detail_shows_its_status_history(client, alpha_db):
    from hx import triage as triage_mod

    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _finding(alpha_db, eid, fid="f1")
    triage_mod.set_status(alpha_db, finding_id="f1",
                          to_status="false_positive",
                          note="header is set at the CDN")

    body = client.get("/e/alpha/findings/f1").text

    assert "header is set at the CDN" in body
    assert "human" in body


def test_an_unknown_finding_is_a_404(client):
    assert client.get("/e/alpha/findings/f-nope").status_code == 404


def test_the_exchange_view_shows_both_halves(client, alpha_db, web_base):
    from hx.store.blobs import BlobStore

    blobs = BlobStore(web_base / "alpha" / "blobs")
    req_digest, req_len = blobs.put(b"GET /search?q=1 HTTP/1.1\r\n"
                                    b"Host: alpha.test\r\n\r\n")
    resp_digest, resp_len = blobs.put(b"HTTP/1.1 200 OK\r\n"
                                      b"Content-Type: text/html\r\n\r\n"
                                      b"<b>hello</b>")
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r1',?,'scan','staging',1,'completed')", (eid,))
    alpha_db.execute(
        "INSERT INTO exchange(id, run_id, via, outcome, sent_us, method, url,"
        " status, req_blob, resp_blob, resp_len)"
        " VALUES('x1','r1','send','ok',1,'GET','https://alpha.test/search',"
        f"200,'{req_digest}','{resp_digest}',{resp_len})")

    body = client.get("/e/alpha/exchanges/x1").text

    assert "Host: alpha.test" in body
    assert "Content-Type: text/html" in body


def test_a_hostile_response_body_is_escaped_not_executed(
        client, alpha_db, web_base):
    """THE CORE THREAT of spec section 4, at the screen it actually lands
    on. A response body is attacker-influenced by definition -- half the
    check corpus exists to find places where attacker input comes back in
    one -- and this app renders it into a browser with no authentication in
    front of it.

    MUTATION: pass `autoescape=False` in `render.templates()`. This test
    must go red. It asserts the RAW form is ABSENT rather than that an
    escaped form is present, because a page can hold both.
    """
    from hx.store.blobs import BlobStore

    payload = b"<script>fetch('/e/beta')</script>"
    blobs = BlobStore(web_base / "alpha" / "blobs")
    digest, length = blobs.put(b"HTTP/1.1 200 OK\r\n\r\n" + payload)
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r1',?,'scan','staging',1,'completed')", (eid,))
    alpha_db.execute(
        "INSERT INTO exchange(id, run_id, via, outcome, sent_us, method, url,"
        " status, resp_blob, resp_len)"
        " VALUES('x1','r1','send','ok',1,'GET','https://alpha.test/',200,"
        f"'{digest}',{length})")

    body = client.get("/e/alpha/exchanges/x1").text

    assert payload.decode() not in body
    assert "&lt;script&gt;" in body


def test_an_unreadable_blob_says_so_rather_than_showing_an_empty_body(
        client, alpha_db):
    """S12 at the level of one panel: a body that could not be read must not
    render as a body that was empty. The exchange row names a digest whose
    file was never written.

    MUTATION: catch `CorruptBlob` and return `b""`. This test must go red.
    """
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r1',?,'scan','staging',1,'completed')", (eid,))
    alpha_db.execute(
        "INSERT INTO exchange(id, run_id, via, outcome, sent_us, method, url,"
        " status, resp_blob) VALUES('x1','r1','send','ok',1,'GET',"
        "'https://alpha.test/',200,'" + "0" * 64 + "')")

    body = client.get("/e/alpha/exchanges/x1").text

    assert "could not be read" in body
```

Create `tests/test_credentials_never_reach_the_screen.py`:

```python
"""The screen half of `test_credentials_never_reach_the_store.py`.

Section 7's rule -- a credential value never appears in config.yaml, a
rendered report, `agent_action`, or any log -- has one more surface since
2026-09-01, and it is the one an operator looks at all day.

TWO MECHANISMS, AND ONLY ONE OF THEM IS THIS APP'S. Blob BYTES are redacted
extension-side by `Redactor.java` BEFORE hashing, so what reaches the
exchange screen already carries `{{identity:<id>:authz}}` where a credential
was; this app adds nothing there, and S4 forbids it to -- "Python must never
gain a second place that decides any of them". What IS this app's job is the
URL COLUMNS, where `http://user:pass@host/` reached `exchange.url` and
`denial.url` verbatim until `records.redact_url` was written. The screen
calls that same function and no other.
"""
from __future__ import annotations

SECRET = "hunter2correcthorse"


def _exchange_with_userinfo(conn, eid):
    conn.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r1',?,'scan','staging',1,'completed')", (eid,))
    conn.execute(
        "INSERT INTO exchange(id, run_id, via, outcome, sent_us, method, url,"
        " status) VALUES('x1','r1','send','ok',1,'GET',"
        f"'https://admin:{SECRET}@alpha.test/panel',200)")


def test_url_userinfo_never_reaches_the_exchange_screen(client, alpha_db):
    """MUTATION: remove `| redact` from the URL in `exchange.html`.
    This test must go red."""
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _exchange_with_userinfo(alpha_db, eid)

    body = client.get("/e/alpha/exchanges/x1").text

    assert SECRET not in body
    assert "alpha.test/panel" in body


def test_url_userinfo_never_reaches_the_finding_screen(client, alpha_db):
    """The same secret, one screen along. Two halves of one request redacted
    by two different rules is how a page ends up quoting the credential out
    of the column beside the blob that does not have it."""
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _exchange_with_userinfo(alpha_db, eid)
    alpha_db.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES('f1',?,'k1','Exposed panel','High','Firm','check','new',"
        "'surface')", (eid,))
    alpha_db.execute(
        "INSERT INTO evidence(id, finding_id, seq, role, kind, exchange_id,"
        " captured_us) VALUES('ev1','f1',1,'proof','exchange','x1',1)")

    body = client.get("/e/alpha/findings/f1").text

    assert SECRET not in body


def test_the_scope_patterns_on_the_overview_are_redacted(client, web_base):
    """Standing ruling R1 from the report's own review: text an OPERATOR
    authored is not exempt. A credential reaches a scope pattern the same
    way it reaches a `--client` string.

    MUTATION: remove `| redact` from the scope list in `overview.html`.
    """
    from hx import config as config_mod
    from hx import engagement as eng_mod
    from starlette.testclient import TestClient

    from hx.web.app import create_app

    cfg = config_mod.Config(
        name="creds", client="C", safety_profile="staging",
        scope_include=[f"https://admin:{SECRET}@creds.test/*"])
    eng_mod.create(web_base / "creds", cfg, author="test").db.close()

    with TestClient(create_app(web_base),
                    base_url="http://127.0.0.1:8901") as c:
        body = c.get("/e/creds").text

    assert SECRET not in body
    assert "creds.test" in body
```

- [ ] **Step 2: Run them to verify they fail**

```bash
.venv/bin/pytest tests/test_credentials_never_reach_the_screen.py -q
```

Expected: FAIL with 404s from the two missing routes.

- [ ] **Step 3: Add the reads**

Append to `src/hx/web/reads.py`, and add `from hx import triage as triage_mod`
and `from hx.store.blobs import CorruptBlob` to its imports:

```python
#: The encoding every captured byte is shown through, matching
#: `tools/impl/http.py`'s own `TEXT`. latin-1 round-trips all 256 byte
#: values, so the viewer shows what was actually on the wire and agrees
#: with what `http.grep` matched against. utf-8 with `errors="replace"`
#: would show a body the target never sent.
TEXT = "latin-1"


def finding_detail(conn: sqlite3.Connection, finding_id: str) -> dict | None:
    row = conn.execute(
        "SELECT f.id, f.title, f.description, f.impact, f.remediation, f.cwe,"
        " f.references_json, f.severity, f.severity_source, f.confidence,"
        " f.created_by, f.status, f.check_id, f.issue_type_id, f.payload,"
        " f.insertion_name, f.insertion_kind, f.host, f.scope_level,"
        " f.first_seen_run, f.last_seen_run, s.method, s.path_template"
        " FROM finding f LEFT JOIN surface s ON s.id = f.surface_id"
        " WHERE f.id=?", (finding_id,)).fetchone()
    if row is None:
        return None
    keys = ("id", "title", "description", "impact", "remediation", "cwe",
            "references_json", "severity", "severity_source", "confidence",
            "created_by", "status", "check_id", "issue_type_id", "payload",
            "insertion_name", "insertion_kind", "host", "scope_level",
            "first_seen_run", "last_seen_run", "method", "path_template")
    return dict(zip(keys, row))


def evidence(conn: sqlite3.Connection, finding_id: str) -> tuple:
    """The evidence chain, in the order it was attached.

    Joined out to the exchange so a row can be read without a second click:
    what was sent, what came back, and whether the exchange completed at
    all. `outcome` is on the row deliberately -- evidence pointing at a
    timed-out exchange is evidence of nothing, and a chain that hid that
    would let a finding look better supported than it is.
    """
    rows = conn.execute(
        "SELECT e.id, e.seq, e.role, e.kind, e.exchange_id, e.ref, e.note,"
        " e.captured_us, x.method, x.url, x.status, x.outcome"
        " FROM evidence e LEFT JOIN exchange x ON x.id = e.exchange_id"
        " WHERE e.finding_id=? ORDER BY e.seq, e.id", (finding_id,)).fetchall()
    keys = ("id", "seq", "role", "kind", "exchange_id", "ref", "note",
            "captured_us", "method", "url", "status", "outcome")
    return tuple(dict(zip(keys, r)) for r in rows)


def observations(conn: sqlite3.Connection, finding_id: str) -> tuple:
    """Whether each run still saw this finding.

    `observed = 0` on the latest run is what the report renders as "appears
    fixed; verify before closing", and the screen must be able to say the
    same thing -- a retest whose result lives only in the deliverable is a
    retest the operator cannot check before shipping it.
    """
    rows = conn.execute(
        "SELECT o.run_id, o.observed, o.severity_at, o.confidence_at,"
        " o.ts_us, r.kind, r.status FROM finding_observation o"
        " JOIN run r ON r.id = o.run_id WHERE o.finding_id=?"
        " ORDER BY o.ts_us, o.run_id", (finding_id,)).fetchall()
    keys = ("run_id", "observed", "severity_at", "confidence_at", "ts_us",
            "kind", "status")
    return tuple(dict(zip(keys, r)) for r in rows)


def _body(blobs, digest, expected_len=None) -> tuple[str, str | None]:
    """One blob as text, or an honest account of why it is not here.

    Returns `(text, problem)`. A body that COULD NOT BE READ must never
    render as a body that was EMPTY -- that is S12's distinction at the
    level of one panel, and returning `b""` on `CorruptBlob` is exactly the
    collapse it forbids.
    """
    if digest is None:
        return "", None
    try:
        return blobs.get(digest, expected_len).decode(TEXT), None
    except CorruptBlob as exc:
        return "", f"this body could not be read: {exc}"
    except OSError as exc:
        return "", f"this body could not be read: {exc}"


def exchange(conn: sqlite3.Connection, blobs, exchange_id: str) -> dict | None:
    """One exchange, both halves, as text.

    NO REDACTION HAPPENS HERE. `Redactor.java` runs extension-side before
    hashing, so these bytes already carry `{{identity:<id>:authz}}` and
    `{{observed:set-cookie}}` where credentials were. S4: Python must never
    gain a second place that decides any of this. The URL COLUMN is
    different and is redacted in the template, through `records.redact_url`
    -- the rule the Java side already shares character for character.
    """
    row = conn.execute(
        "SELECT id, run_id, surface_id, via, outcome, sent_us, recv_us,"
        " method, url, status, req_blob, resp_blob, resp_len, body_shed,"
        " identity, identity_state, resolved_ip"
        " FROM exchange WHERE id=?", (exchange_id,)).fetchone()
    if row is None:
        return None
    keys = ("id", "run_id", "surface_id", "via", "outcome", "sent_us",
            "recv_us", "method", "url", "status", "req_blob", "resp_blob",
            "resp_len", "body_shed", "identity", "identity_state",
            "resolved_ip")
    out = dict(zip(keys, row))
    out["request"], out["request_problem"] = _body(blobs, row[10])
    out["response"], out["response_problem"] = _body(blobs, row[11], row[12])
    return out
```

- [ ] **Step 4: Add the routes**

In `app.py`, add `from hx import triage as triage_mod` and
`from hx.store.blobs import BlobStore` to the imports, then:

```python
def finding(request):
    entry = _entry(request)
    conn = registry_mod.open_read(entry)
    try:
        detail = reads_mod.finding_detail(conn, request.path_params["fid"])
        if detail is None:
            raise HTTPException(status_code=404)
        context = {
            "entry": entry,
            "finding": detail,
            "evidence": reads_mod.evidence(conn, detail["id"]),
            "observations": reads_mod.observations(conn, detail["id"]),
            "history": triage_mod.history(conn, detail["id"]),
            "targets": triage_mod.TARGETS,
            "note_required": triage_mod.NOTE_REQUIRED,
        }
    finally:
        conn.close()
    return request.app.state.templates.TemplateResponse(
        request, "finding.html", context)


def exchange(request):
    entry = _entry(request)
    conn = registry_mod.open_read(entry)
    try:
        data = reads_mod.exchange(conn, BlobStore(entry.path / "blobs"),
                                  request.path_params["xid"])
        if data is None:
            raise HTTPException(status_code=404)
    finally:
        conn.close()
    return request.app.state.templates.TemplateResponse(
        request, "exchange.html", {"entry": entry, "exchange": data})
```

and the routes:

```python
            Route("/e/{name}/findings/{fid}", finding),
            Route("/e/{name}/exchanges/{xid}", exchange),
```

**`/e/{name}/findings/{fid}` must be registered AFTER `/e/{name}/findings`.**
Starlette matches in order, and the two do not collide, but keeping the
list before the detail is the readable order and matches the URL hierarchy.

`BlobStore(...)` calls `secure_mkdir` on its `tmp/` directory, so it needs a
writable engagement directory. That is not a write to the STORE — no
database, blob or config file is touched — and the directory it may create
lands at `0700` like every other. Note it in the review: it is the one
filesystem side effect a GET has.

- [ ] **Step 5: Create the two templates**

`src/hx/web/templates/finding.html`:

```html
{% extends "base.html" %}
{% block title %}{{ finding.title }}{% endblock %}
{% block crumb %}<span class="crumb"><a href="/e/{{ entry.name }}">{{ entry.name }}</a> · <a href="/e/{{ entry.name }}/findings">findings</a></span>{% endblock %}
{% block content %}
<h1><span class="sev sev-{{ finding.severity | lower }}">{{ finding.severity }}</span> {{ finding.title }}</h1>
<p class="muted">
  {{ finding.confidence }} ·
  {% if finding.path_template %}<code>{{ finding.method }} {{ finding.path_template }}</code>{% else %}{{ finding.host or "engagement-wide" }}{% endif %} ·
  found by <code>{{ finding.check_id or finding.created_by }}</code> ·
  <span class="status status-{{ finding.status }}">{{ finding.status }}</span>
</p>

{% if finding.description %}<h2>Description</h2><p>{{ finding.description | redact }}</p>{% endif %}
{% if finding.impact %}<h2>Impact</h2><p>{{ finding.impact | redact }}</p>{% endif %}
{% if finding.remediation %}<h2>Remediation</h2><p>{{ finding.remediation | redact }}</p>{% endif %}
{% if finding.cwe %}<p class="muted">{{ finding.cwe }}</p>{% endif %}
{% if finding.payload %}<h2>Payload</h2><pre class="bytes">{{ finding.payload }}</pre>{% endif %}

<h2>Evidence</h2>
{% if not evidence %}
<p class="warn">No evidence is attached to this finding. There is nothing
here to check it against.</p>
{% else %}
<table>
<thead><tr><th class="num">#</th><th>Role</th><th>Exchange</th><th>Outcome</th><th>Note</th></tr></thead>
<tbody>
{% for e in evidence %}
<tr>
  <td class="num">{{ e.seq }}</td>
  <td>{{ e.role }}</td>
  <td>
    {% if e.exchange_id %}
      <a href="/e/{{ entry.name }}/exchanges/{{ e.exchange_id }}">{{ e.exchange_id }}</a>
      <span class="muted">{{ e.method }} {{ e.url | redact }} → {{ e.status if e.status is not none else "—" }}</span>
    {% else %}
      <span class="muted">{{ e.kind }} {{ e.ref or "" }}</span>
    {% endif %}
  </td>
  <td>{{ e.outcome or "—" }}</td>
  <td>{{ e.note | redact if e.note else "—" }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% endif %}

<h2>Seen in</h2>
{% if not observations %}
<p class="muted">No run has recorded an observation for this finding.</p>
{% else %}
<table>
<thead><tr><th>Run</th><th>Kind</th><th>Observed</th><th>When</th></tr></thead>
<tbody>
{% for o in observations %}
<tr>
  <td>{{ o.run_id }}</td><td>{{ o.kind }}</td>
  <td>{{ "yes" if o.observed else "no — appears fixed; verify before closing" }}</td>
  <td>{{ o.ts_us | when }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% endif %}

<h2>Triage history</h2>
{% if not history %}
<p class="muted">Never triaged.</p>
{% else %}
<table>
<thead><tr><th>When</th><th>Change</th><th>By</th><th>Note</th></tr></thead>
<tbody>
{% for h in history %}
<tr>
  <td>{{ h[4] | when }}</td>
  <td>{{ h[0] or "—" }} → {{ h[1] }}</td>
  <td>{{ h[2] }}</td>
  <td>{{ h[3] | redact if h[3] else "—" }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% endif %}
{% block triage %}{% endblock %}
{% endblock %}
```

The empty `{% block triage %}` is where Task 6 puts the form. It renders
nothing now, and it exists so that Task 6 is an addition rather than a
rewrite of a screen that already has tests.

`src/hx/web/templates/exchange.html`:

```html
{% extends "base.html" %}
{% block title %}{{ exchange.id }}{% endblock %}
{% block crumb %}<span class="crumb"><a href="/e/{{ entry.name }}">{{ entry.name }}</a> · exchange</span>{% endblock %}
{% block content %}
<h1><code>{{ exchange.method }} {{ exchange.url | redact }}</code></h1>
<p class="muted">
  {{ exchange.id }} · via {{ exchange.via }} ·
  outcome <strong>{{ exchange.outcome }}</strong> ·
  status {{ exchange.status if exchange.status is not none else "—" }} ·
  sent {{ exchange.sent_us | when }}
  {% if exchange.identity %}· as <code>{{ exchange.identity }}</code>
  ({{ exchange.identity_state }}){% endif %}
</p>
{% if exchange.body_shed %}
<p class="warn">This exchange's body was <strong>shed</strong> — the store
kept the metadata and not the bytes. What is below is not the whole
response.</p>
{% endif %}

<h2>Request</h2>
{% if exchange.request_problem %}
<p class="warn">{{ exchange.request_problem }}</p>
{% elif not exchange.req_blob %}
<p class="muted">No request was stored for this exchange.</p>
{% else %}
<pre class="bytes">{{ exchange.request }}</pre>
{% endif %}

<h2>Response</h2>
{% if exchange.response_problem %}
<p class="warn">{{ exchange.response_problem }}</p>
{% elif not exchange.resp_blob %}
<p class="muted">No response was stored for this exchange.</p>
{% else %}
<pre class="bytes">{{ exchange.response }}</pre>
{% endif %}

<p class="muted">Credentials this extension injected are already replaced in
these bytes — redaction runs inside the JVM, before hashing, so the store
never held them.</p>
{% endblock %}
```

- [ ] **Step 6: Run the tests and the gate**

```bash
.venv/bin/pytest tests/test_web_screens.py \
    tests/test_credentials_never_reach_the_screen.py -q
.venv/bin/pytest -q
.venv/bin/ruff check src tests
awk 'length>88 {print FILENAME": "FNR}' src/hx/web/reads.py src/hx/web/app.py
```

Expected: all PASS, ruff clean, no long lines.

- [ ] **Step 7: Commit**

```bash
git add src/hx/web tests/test_web_screens.py \
    tests/test_credentials_never_reach_the_screen.py
git commit -m "feat(web): the finding a human triages, and the exchange behind it"
```

---

## Task 6: The two human acts, over HTTP

STOP and triage — §11's *"control in v1 is exactly two things"* — plus the
cross-site guard that only becomes testable now that a POST exists.

**Why the Origin check is here and not in Task 3.** Task 3 wrote no
state-changing route, so a guard added there would have shipped untested
against nothing. It arrives with the first POST and with a test that asserts
the **finding's status is unchanged**, not merely that a 403 came back — a
403 alone passes a handler that writes the row and then rejects.

**POST handlers are `async def`.** `request.form()` is a coroutine and a
sync handler cannot await it. The SQLite write then goes through
`run_in_threadpool`, so a write never blocks the event loop. The forms are
`application/x-www-form-urlencoded`, which Starlette parses natively —
**`python-multipart` is not needed and must not be added**; it is only
required for `multipart/form-data`, and nothing here uploads a file.

**Files:**
- Modify: `src/hx/web/app.py` (`SAFE_METHODS`, `_same_origin`, `_guard`, two routes, halt state on the overview)
- Modify: `src/hx/web/templates/finding.html` (the triage form)
- Modify: `src/hx/web/templates/overview.html` (the halt banner and STOP)
- Create: `tests/test_web_writes.py`

**Interfaces:**
- Consumes: `hx.triage.set_status`, `hx.triage.TARGETS`,
  `hx.halt.OperatorHalt`, `hx.store.db.connect`
- Produces: `hx.web.app.SAFE_METHODS: frozenset[str]`,
  `hx.web.app._same_origin(request) -> bool`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_web_writes.py`.

```python
"""The two acts S8 forbids the agent, and the guard on the way in."""
from __future__ import annotations

ORIGIN = {"Origin": "http://127.0.0.1:8901"}


def _finding(conn, fid="f1", status="new"):
    eid = conn.execute("SELECT id FROM engagement").fetchone()[0]
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES(?,?,?,'Missing HSTS','Low','Firm','check',?,'surface')",
        (fid, eid, f"k-{fid}", status))
    return eid


def _status(conn, fid="f1"):
    return conn.execute("SELECT status FROM finding WHERE id=?",
                        (fid,)).fetchone()[0]


def _events(conn, fid="f1"):
    return conn.execute(
        "SELECT COUNT(*) FROM finding_status_event WHERE finding_id=?",
        (fid,)).fetchone()[0]


def test_a_same_origin_post_confirms_the_finding(client, alpha_db):
    _finding(alpha_db)

    response = client.post("/e/alpha/findings/f1/status",
                           data={"status": "confirmed"}, headers=ORIGIN,
                           follow_redirects=False)

    assert response.status_code == 303
    assert _status(alpha_db) == "confirmed"


def test_a_post_with_no_origin_is_refused_and_changes_nothing(
        client, alpha_db):
    """THE STATUS ASSERTION IS THE TEST. A 403 alone passes a handler that
    writes the row and then rejects, which is exactly the bug this guards.

    MUTATION: delete the `_same_origin` branch from `_guard`. This test
    must go red.
    """
    _finding(alpha_db)

    response = client.post("/e/alpha/findings/f1/status",
                           data={"status": "confirmed"},
                           follow_redirects=False)

    assert response.status_code == 403
    assert _status(alpha_db) == "new"
    assert _events(alpha_db) == 0


def test_a_post_from_another_origin_is_refused_and_changes_nothing(
        client, alpha_db):
    """Another web app on this machine is not this web app. Checking the
    origin's HOST against the allowlist rather than the full origin would
    let `http://localhost:9999` write here.

    MUTATION: compare only the origin's hostname against ALLOWED_HOSTS
    instead of the whole origin against this request's own. Must go red.
    """
    _finding(alpha_db)

    for hostile in ("http://localhost:9999", "https://attacker.example",
                    "http://127.0.0.1:9999", "null"):
        response = client.post("/e/alpha/findings/f1/status",
                               data={"status": "confirmed"},
                               headers={"Origin": hostile},
                               follow_redirects=False)
        assert response.status_code == 403, hostile

    assert _status(alpha_db) == "new"
    assert _events(alpha_db) == 0


def test_a_cross_site_fetch_metadata_header_is_refused(client, alpha_db):
    """`Sec-Fetch-Site` is the browser's own account of where a request came
    from, and it wins over `Origin` when present because a page cannot
    forge it."""
    _finding(alpha_db)

    response = client.post(
        "/e/alpha/findings/f1/status", data={"status": "confirmed"},
        headers={**ORIGIN, "Sec-Fetch-Site": "cross-site"},
        follow_redirects=False)

    assert response.status_code == 403
    assert _status(alpha_db) == "new"


def test_reads_are_not_affected_by_the_origin_check(client):
    """The control. A guard applied to GET would make the whole app
    unusable from a link, and every other test here would still pass."""
    assert client.get("/e/alpha").status_code == 200


def test_dismissing_without_a_note_is_refused_over_http(client, alpha_db):
    _finding(alpha_db)

    response = client.post("/e/alpha/findings/f1/status",
                           data={"status": "false_positive", "note": "  "},
                           headers=ORIGIN, follow_redirects=False)

    assert response.status_code == 400
    assert "note is required" in response.text
    assert _status(alpha_db) == "new"
    assert _events(alpha_db) == 0


def test_a_dismissal_with_a_note_records_it(client, alpha_db):
    _finding(alpha_db)

    client.post("/e/alpha/findings/f1/status",
                data={"status": "false_positive",
                      "note": "header is set at the CDN"},
                headers=ORIGIN, follow_redirects=False)

    assert _status(alpha_db) == "false_positive"
    assert alpha_db.execute(
        "SELECT note FROM finding_status_event WHERE finding_id='f1'"
    ).fetchone()[0] == "header is set at the CDN"


def test_a_status_outside_the_two_is_refused_over_http(client, alpha_db):
    _finding(alpha_db)

    response = client.post("/e/alpha/findings/f1/status",
                           data={"status": "reported"}, headers=ORIGIN,
                           follow_redirects=False)

    assert response.status_code == 400
    assert _status(alpha_db) == "new"


def test_stop_writes_the_sentinel_and_an_operator_row(
        client, alpha_db, web_base):
    """STOP is a route over `halt.OperatorHalt`, unchanged. The sentinel is
    the mechanism that actually stops the extension -- it polls the file and
    it works when the bridge is dead -- and the row is what explains the
    stop afterwards."""
    response = client.post("/e/alpha/halt", data={"reason": "client called"},
                           headers=ORIGIN, follow_redirects=False)

    assert response.status_code == 303
    assert (web_base / "alpha" / "HALTED").exists()
    row = alpha_db.execute(
        "SELECT actor, tool, why FROM agent_action WHERE tool='halt'"
    ).fetchone()
    assert row[0] == "operator"
    assert row[2] == "client called"


def test_a_halted_engagement_says_so_on_the_overview(client, web_base):
    """S4: an unreadable sentinel IS halted -- "unknown state is stop" --
    and `OperatorHalt.halted` is a union of the file and the store. The
    banner follows that rule rather than inventing an "unknown"."""
    (web_base / "alpha" / "HALTED").write_text("stopped by hand\n1\n")

    body = client.get("/e/alpha").text

    assert "HALTED" in body
    assert "stopped by hand" in body
    assert "hx resume" in body


def test_stop_is_refused_cross_origin(client, web_base):
    """MUTATION: exempt `/halt` from the guard. Must go red."""
    response = client.post("/e/alpha/halt", data={"reason": "x"},
                           headers={"Origin": "https://attacker.example"},
                           follow_redirects=False)

    assert response.status_code == 403
    assert not (web_base / "alpha" / "HALTED").exists()
```

- [ ] **Step 2: Run them to verify they fail**

```bash
.venv/bin/pytest tests/test_web_writes.py -q
```

Expected: FAIL — 405 Method Not Allowed on every POST, since neither route
exists.

- [ ] **Step 3: Add the guard to `src/hx/web/app.py`**

Add the imports:

```python
from starlette.concurrency import run_in_threadpool
from starlette.responses import RedirectResponse

from hx import halt as halt_mod
from hx import triage as triage_mod
from hx.store import db as db_mod
```

Add the constant beside `CSP`:

```python
#: Methods that cannot change anything, and so need no cross-site guard.
#: HEAD and OPTIONS are here because a guard that broke them would break
#: ordinary browsers on a read-only app.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
```

Add the check above `_guard`:

```python
def _same_origin(request) -> bool:
    """Whether a state-changing request came from this app's own pages.

    `Sec-Fetch-Site` FIRST and decisively: it is the browser's own account
    of where the request came from, and a page cannot forge it. When it is
    absent -- an older browser, or a client that is not a browser -- the
    fallback is an exact `Origin` match against THIS request's own origin.

    Exact, not "the origin's host is in ALLOWED_HOSTS": another web app on
    this machine is not this web app, and a host-level comparison would let
    anything on `localhost:9999` write into a client engagement.

    Neither header present is a REFUSAL. Fail closed: the operator has
    `hx triage` and `hx halt` for the no-browser case, and the cost of the
    strict answer is a curl command that needs one more flag, against a
    silent write from a page the operator merely visited.
    """
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None:
        return fetch_site == "same-origin"
    origin = request.headers.get("origin")
    if not origin:
        return False
    return origin == f"{request.url.scheme}://{request.headers.get('host', '')}"
```

and the branch inside `_guard`, immediately after the Host check:

```python
    if request.method not in SAFE_METHODS and not _same_origin(request):
        # REFUSED BEFORE THE HANDLER RUNS, which is the whole point: a guard
        # that rejects after writing is not a guard, and the tests assert
        # the finding's status is unchanged rather than only that a 403 came
        # back.
        return PlainTextResponse("cross-site write refused", status_code=403)
```

- [ ] **Step 4: Add the two routes**

```python
async def triage_post(request):
    entry = _entry(request)
    form = await request.form()
    finding_id = request.path_params["fid"]
    to_status = form.get("status")
    note = form.get("note")

    def write():
        conn = db_mod.connect(entry.path / "hx.db")
        try:
            return triage_mod.set_status(
                conn, finding_id=finding_id,
                to_status=to_status if isinstance(to_status, str) else "",
                note=note if isinstance(note, str) else None)
        finally:
            conn.close()

    try:
        await run_in_threadpool(write)
    except triage_mod.TriageError as exc:
        return PlainTextResponse(str(exc), status_code=400)
    # POST/redirect/GET: a reload must not re-submit a triage decision.
    return RedirectResponse(f"/e/{entry.name}/findings/{finding_id}",
                            status_code=303)


async def halt_post(request):
    entry = _entry(request)
    form = await request.form()
    given = form.get("reason")
    reason = (given.strip() if isinstance(given, str) else "") or \
        "stopped from the web app"

    def write():
        conn = db_mod.connect(entry.path / "hx.db")
        try:
            halt_mod.OperatorHalt(entry.path, conn).halt(reason)
        finally:
            conn.close()

    await run_in_threadpool(write)
    return RedirectResponse(f"/e/{entry.name}", status_code=303)
```

and the routes:

```python
            Route("/e/{name}/findings/{fid}/status", triage_post,
                  methods=["POST"]),
            Route("/e/{name}/halt", halt_post, methods=["POST"]),
```

- [ ] **Step 5: Put the halt state on the overview**

In `app.py`'s `overview` handler, inside the `try`, after `data = ...`:

```python
        # Through OperatorHalt rather than by testing for the file, so this
        # sees a halt recorded in the STORE as well as one on disk --
        # `halted` is a union, and the two disagree when a harness died
        # between the two writes. A read-only connection is enough: the
        # constructor and both properties only SELECT.
        halt_state = halt_mod.OperatorHalt(entry.path, conn)
        data["halted"] = halt_state.halted
        data["halt_reason"] = halt_state.reason
```

and in `overview.html`, immediately after the `<h1>`:

```html
{% if halted %}
<p class="halted"><strong>HALTED</strong> — {{ halt_reason }}<br>
Issuance is stopped. <strong>Only <code>hx resume</code> lifts it</strong>,
and it records who did: stopping is one click, un-stopping is a deliberate
trip to a terminal.</p>
{% else %}
<form method="post" action="/e/{{ entry.name }}/halt" class="stop">
  <input type="text" name="reason" placeholder="why (optional)">
  <button type="submit" class="danger">STOP issuance</button>
</form>
{% endif %}
```

- [ ] **Step 6: Put the triage form on the finding screen**

In `finding.html`, replace `{% block triage %}{% endblock %}` with:

```html
<h2>Triage</h2>
<p class="muted">Confirming a finding is a human act — the agent cannot do
it, and the record of who decided what is append-only.</p>
<form method="post" action="/e/{{ entry.name }}/findings/{{ finding.id }}/status" class="triage">
  <label>Decision
    <select name="status">
      {% for t in targets %}
      <option value="{{ t }}" {{ 'selected' if t == finding.status else '' }}>{{ t }}</option>
      {% endfor %}
    </select>
  </label>
  <label>Note
    <input type="text" name="note" size="60"
           placeholder="required to dismiss — it reaches the client report">
  </label>
  <button type="submit">Record</button>
</form>
```

- [ ] **Step 7: Run everything**

```bash
.venv/bin/pytest tests/test_web_writes.py -q
.venv/bin/pytest -q
.venv/bin/ruff check src tests
awk 'length>88 {print FILENAME": "FNR}' src/hx/web/app.py
```

Expected: all PASS, ruff clean, no long lines, integration count still 46.

- [ ] **Step 8: Prove the mutations actually kill the tests**

One at a time, on a clean tree — batching misattributes results.

| Mutation | Test that must go red |
|---|---|
| Delete the Host branch from `_guard` | `test_a_foreign_host_header_is_refused` |
| Delete the `_same_origin` branch from `_guard` | `test_a_post_with_no_origin_is_refused_and_changes_nothing` |
| `autoescape=False` in `render.templates()` | `test_a_hostile_response_body_is_escaped_not_executed` |
| `readonly=False` in `registry.open_read` | `test_the_read_path_cannot_write` |
| `registry.lookup` → `base / name` in `_entry` | `test_a_name_the_scan_did_not_return_is_a_404` |
| `_body` returns `b""` on `CorruptBlob` | `test_an_unreadable_blob_says_so_rather_than_showing_an_empty_body` |
| `reads._run_rows` returns `row[2]` unconditionally | `test_a_running_run_with_a_dead_heartbeat_renders_as_error` |
| Remove `\| redact` from `exchange.html`'s URL | `test_url_userinfo_never_reaches_the_exchange_screen` |
| `findings` ignores an unknown filter value | `test_an_unknown_filter_value_is_refused_rather_than_ignored` |

For each: apply it, run the named test, confirm it FAILS, revert with
`git checkout -- <file>`, and record the result. **A mutation that leaves
the suite green means the test is vacuous** — this repo has shipped two of
those, and both looked exactly like a passing test.

- [ ] **Step 9: Commit**

```bash
git add src/hx/web tests/test_web_writes.py
git commit -m "feat(web): STOP and triage, and the guard that refuses a page you merely visited"
```

---

## Finishing the plan

- [ ] **Step 1: Arm the plan-drift markers**

Every ```python block in this plan describing a file that now exists must
gain its `# <path>` first line, and every excerpt block must be a contiguous
run of the file byte for byte. `scripts/sync_plan_block.py "marker@start-end"`
does the excerpt case. ```html and ```bash and ```toml fences are never
scanned and take no marker.

**Do not add `plan-drift: pending`.**
`2026-08-27-checks-and-reporting.md` holds it and at most one plan may.

```bash
.venv/bin/pytest tests/test_plan_matches_repo.py -q
```

It will fail on the count. Update `EXPECTED_BLOCKS` to the number reported
and **name the blocks in the commit message** — the constant exists so that
a number moving is a decision somebody wrote down.

- [ ] **Step 2: Record the debts in `docs/DECISIONS.md`**

Add a `## The web app` chapter covering: why Starlette and not FastAPI (with
the 15-against-9 measurement); why reads do not go through the tool layer
(`journal.record` defaults to `actor="agent"`); why coverage was extracted
and nothing else; and why the app can stop but not start.

Then these rows in the known-debt table:

| Debt | Why it is not paid |
|---|---|
| `--root` means the engagements PARENT to `hx new` and one engagement's OWN directory to every other command; `hx web --base` is a third name for the first meaning | Renaming a flag on six merged commands is a breaking change to an operator's muscle memory and to any script they have written, in exchange for tidiness. `--base` is a new name that does not inherit the ambiguity. |
| No authentication, and no non-loopback binding | S11 sets the terms: a per-install bearer token lands *before* the first write endpoint on a wider binding. Neither is needed while the Host allowlist and loopback binding hold. |
| A GET can create `blobs/tmp/` via `BlobStore.__init__` | The one filesystem side effect on a read path. It creates a directory at `0700` inside an engagement that already exists and touches no database, blob or config file. Removing it means a read-only BlobStore constructor, which is a change to a module three other callers share. |
| Triage has no optimistic concurrency | Two operators triaging one finding both get events recorded and the last wins the cached projection. The log is append-only, so the race is visible rather than silent. |
| The web app does not render `denial` rows | The overview shows what was tested and found; what was REFUSED is a fourth screen, and S11's screen list does not name one. `hx info` and the report both show denial counts today. |

- [ ] **Step 3: Update `README.md`**

Add a `hx web` section next to `hx mcp`: what it serves, that it binds
`127.0.0.1` only and has no `--host`, that `--base` is the engagements
parent directory, and that the only two things it can change are a finding's
triage status and the halt. Add `hx triage` beside it, noting it is the same
act from a terminal.

- [ ] **Step 4: The full gate**

```bash
extension/build.sh                    # never run test.sh last; it leaves the jar stale
.venv/bin/pytest -q
.venv/bin/pytest -m integration -q
.venv/bin/ruff check src tests
.venv/bin/mypy src/hx || true         # non-blocking, as CI has it
awk 'length>88 {print FILENAME": "FNR}' $(git ls-files 'src/**/*.py' 'tests/*.py')
extension/test.sh                     # unchanged by this plan; prove it
extension/build.sh                    # test.sh leaves the jar stale; rebuild
```

All green, the integration count still **46**, and the Java suite still
**ALL PASS** — this plan changes no Java and the run proves it.

---

## Self-Review

**Spec coverage.** Every section of `2026-09-01-web-app-design.md` maps to a
task:

| Spec | Task |
|---|---|
| §3.1 entry point, no `--host` | 3 (step 13) |
| §3.2 dependencies and layout | 3 (step 1) |
| §3.3 registry as allowlist | 3 (steps 2–5) |
| §3.4 fresh read-only connection per request | 3 (`registry.open_read`) |
| §3.5 stale rendered, never reaped | 1 (`run.is_stale`), 3 (`reads._run_rows`) |
| §4 threat model, all eight rows | 3 (Host, CSP, nosniff, XSS, readonly, traversal), 5 (redaction), 6 (Origin) |
| §5.1 reads not through the tool layer | 3 (`reads.py` docstring and structure) |
| §5.2 coverage extracted, and only coverage | 1 |
| §6.1 the eight Plan A routes | 3, 4, 5, 6 |
| §6.3 stop but not start; halt renders as the extension reads it | 6 |
| §7.1 STOP over `OperatorHalt` | 6 |
| §7.2 `triage.py`, all six decisions | 2 |
| §7.3 the note reaches the report | 2 (steps 10–12) |
| §9 testing, all four families | 1–6, and the mutation pass in 6 step 8 |
| §11 master spec amendment | landed with the spec, commit `6d26738` |

**Known deviations, both deliberate and both stated at the task that makes
them:**

1. **No htmx in Plan A** (Task 3). The spec's file structure names it; Plan
   A has nothing for it to do, and vendoring an unused library would add a
   supply-chain step for nothing. Plan A's CSP is `script-src 'none'` as a
   result, which is stronger than the spec's `'self'`. Plan B vendors it and
   widens the policy in the same visible change.
2. **`tests/test_credentials_never_reach_the_screen.py` lands in Task 5**,
   not Task 3, because URLs first reach a page there. The `redact` filter is
   registered in Task 3 and exercised end-to-end in Task 5.

**Type consistency.** `Coverage` fields are read as `cov.captured`,
`cov.scanned`, `cov.unfinished`, `cov.untested`, `cov.by_check`,
`cov.reasons` in Task 1's `report.py` edit, Task 3's `reads.overview`, and
`overview.html`. `StatusChange` is read as `.changed`, `.from_status`,
`.to_status` in Task 2's CLI and nowhere else — it has no `note_line`.
`Entry` is read as `.name`, `.path`, `.engagement_id`, `.client`,
`.created_us`, `.status`, `.problem`, `.findings`, `.runs` across Tasks 3–6.
`reads.findings` takes `severity=` and `status=` in both its definition and
its only caller.

**One thing a reviewer should push on.** `reads.py` ends this plan at
roughly 300 lines with seven query functions. The File Structure section
sets 400 as the line at which it splits per screen. Plan B adds the exchange
list, the run-progress query and the transcript — it will cross that line,
and the split belongs at the start of Plan B rather than as an afterthought
at the end of it.
