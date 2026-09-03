# hx Engagement Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the per-engagement persistence layer — SQLite schema, content-addressed blob store, config, and the `hx new` / `hx info` CLI — so every later subsystem has somewhere durable and isolated to write.

**Architecture:** One directory per engagement, mode 0700, containing its own SQLite database, its own `blobs/` tree, and its own `config.yaml`. Nothing is shared between engagements — this is the structural guarantee that client A's bytes cannot reach client B's report. SQLite runs in WAL mode with exactly one writer connection; the blob store writes to a temp file, fsyncs, verifies the digest of what actually landed, then atomically renames.

**Tech Stack:** Python 3.12+ (3.14.7 available), `uv` for env management, stdlib `sqlite3`, `PyYAML`, `click` for CLI, `pytest`.

**Spec:** `docs/superpowers/specs/2026-08-21-hx-design.md` (§3 Architecture, §5 Data model)

## Global Constraints

- Python 3.12 minimum; target the installed 3.14.7.
- Engagement directories are created mode `0o700`; blob and DB files `0o600`. Never looser.
- At every SQLite connection open: `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`, `foreign_keys=ON`. Foreign keys are OFF per-connection by default in SQLite — without this pragma none of the declared relationships are enforced.
- Exactly **one** writer connection per engagement, fed by an in-process queue. Readers use separate connections.
- All timestamps are integer microseconds since epoch, column suffix `_us`. Never floats, never strings.
- `dedupe_key` is one NOT NULL TEXT column; absent parts are the literal `-`, never `NULL`, because SQLite treats NULLs as distinct in a UNIQUE index and would silently defeat the constraint.
- No network access in this plan. Nothing here talks to Burp or to a target.

---

### Task 1: Project scaffold and the schema

**Files:**
- Create: `pyproject.toml`
- Create: `src/hx/__init__.py`
- Create: `src/hx/store/__init__.py`
- Create: `src/hx/store/schema.sql`
- Create: `src/hx/store/db.py`
- Test: `tests/test_db.py`

**Interfaces:**
- Consumes: nothing (first task)
- Produces:
  - `hx.store.db.SCHEMA_VERSION: int`
  - `hx.store.db.connect(path: Path, *, readonly: bool = False) -> sqlite3.Connection` — applies all required pragmas
  - `hx.store.db.init_schema(conn: sqlite3.Connection) -> None` — idempotent
  - `hx.store.db.TABLES: tuple[str, ...]` — the 14 table names, for tests and diagnostics

- [ ] **Step 1: Create the project scaffold**

```toml
# pyproject.toml
[project]
name = "hx"
version = "0.1.0"
description = "Agent-driven web application security assessment harness"
requires-python = ">=3.12"
dependencies = ["PyYAML>=6.0", "click>=8.1"]

[project.scripts]
hx = "hx.cli:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/hx"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
```

```bash
mkdir -p src/hx/store tests
touch src/hx/__init__.py src/hx/store/__init__.py
uv venv .venv
uv pip install --python .venv/bin/python -e . pytest
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_db.py
import sqlite3
from pathlib import Path

import pytest

from hx.store import db


def test_connect_applies_required_pragmas(tmp_path: Path):
    conn = db.connect(tmp_path / "hx.db")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    # 1 == NORMAL. Three of the four spec-mandated pragmas were asserted
    # here and not this one -- the asymmetry is exactly what let it get
    # dropped unnoticed.
    assert conn.execute("PRAGMA synchronous").fetchone()[0] == 1


def test_init_schema_creates_every_table(tmp_path: Path):
    """A subset assertion (`set(db.TABLES) <= present`) passes even if
    TABLES were empty -- assert equality against what the database actually
    has (minus sqlite's own internal tables) so a table dropped from TABLES
    is caught too, not just one missing from the schema."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    present = {
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        if not r[0].startswith("sqlite_")
    }
    assert set(db.TABLES) == present


def test_init_schema_is_idempotent(tmp_path: Path):
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    db.init_schema(conn)  # must not raise
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION


def test_readonly_connection_opens(tmp_path: Path):
    """journal_mode is a write; a readonly connection must not attempt it."""
    path = tmp_path / "hx.db"
    db.init_schema(db.connect(path))
    ro = db.connect(path, readonly=True)
    assert ro.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert ro.execute("SELECT COUNT(*) FROM engagement").fetchone()[0] == 0


def test_readonly_connection_cannot_write(tmp_path: Path):
    """The existing test above only ever reads through the readonly
    connection, so a `mode=ro` typo or a dropped flag would not be caught.
    Prove the connection actually refuses a write."""
    path = tmp_path / "hx.db"
    db.init_schema(db.connect(path))
    ro = db.connect(path, readonly=True)
    with pytest.raises(sqlite3.OperationalError):
        ro.execute(
            "INSERT INTO engagement(id, name, client, created_us, status)"
            " VALUES('e1','acme','Acme',1,'active')"
        )


def test_foreign_keys_are_actually_enforced(tmp_path: Path):
    """A declared FK is worthless if the pragma is off. Prove it bites."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us, status)"
            " VALUES('r1','NO_SUCH_ENGAGEMENT','manual','production',1,'running')"
        )


def test_dedupe_key_uniqueness_holds_per_engagement(tmp_path: Path):
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e1','acme','Acme',1,'active')"
    )
    key = "sqli|https|app.acme.com|443|GET|/order/{n}|url_param|id"
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES('f1','e1',?,'SQLi','High','Firm','agent','new','insertion')",
        (key,),
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
            " confidence, created_by, status, scope_level)"
            " VALUES('f2','e1',?,'SQLi dup','High','Firm','agent','new','insertion')",
            (key,),
        )


def test_connect_sets_file_permissions(tmp_path: Path):
    """Verify directory (0o700) and database file (0o600) have restricted permissions."""
    path = tmp_path / "restricted" / "hx.db"
    db.connect(path)
    assert (path.parent.stat().st_mode & 0o777) == 0o700
    assert (path.stat().st_mode & 0o777) == 0o600


def test_trg_agent_cannot_confirm_blocks_confirmed_status(tmp_path: Path):
    """Agent attempting to set status to 'confirmed' raises IntegrityError."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e1','acme','Acme',1,'active')"
    )
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES('f1','e1','key1','SQLi','High','Firm','agent','new','insertion')"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO finding_status_event(id, finding_id, to_status, actor, ts_us)"
            " VALUES('se1','f1','confirmed','agent',1000)"
        )


def test_trg_agent_cannot_confirm_blocks_reported_status(tmp_path: Path):
    """Agent attempting to set status to 'reported' raises IntegrityError."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e1','acme','Acme',1,'active')"
    )
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES('f1','e1','key1','SQLi','High','Firm','agent','new','insertion')"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO finding_status_event(id, finding_id, to_status, actor, ts_us)"
            " VALUES('se1','f1','reported','agent',1000)"
        )


def test_human_can_confirm_finding(tmp_path: Path):
    """Human actor can set status to 'confirmed' without trigger blocking."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e1','acme','Acme',1,'active')"
    )
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES('f1','e1','key1','SQLi','High','Firm','agent','new','insertion')"
    )
    # Must not raise
    conn.execute(
        "INSERT INTO finding_status_event(id, finding_id, to_status, actor, ts_us)"
        " VALUES('se1','f1','confirmed','human',1000)"
    )


def test_agent_can_set_other_statuses(tmp_path: Path):
    """Agent can set status to statuses other than 'confirmed' and 'reported'."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e1','acme','Acme',1,'active')"
    )
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES('f1','e1','key1','SQLi','High','Firm','agent','new','insertion')"
    )
    # Must not raise
    conn.execute(
        "INSERT INTO finding_status_event(id, finding_id, to_status, actor, ts_us)"
        " VALUES('se1','f1','triaged','agent',1000)"
    )


def test_dangling_first_seen_run_rejected(tmp_path: Path):
    """A dangling first_seen_run reference is rejected by FK constraint.

    MEASURED: this raised `NOT NULL constraint failed:
    surface.normaliser_version` -- and later `surface.discovered_by` -- and
    never reached the foreign key at all. Both columns are deliberately
    DEFAULT-less, so an INSERT that names neither fails before SQLite looks at
    the reference, and `pytest.raises(IntegrityError)` could not tell the two
    apart. The row below is complete except for the one thing under test, and
    the match is on the constraint's own name.
    """
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e1','acme','Acme',1,'active')"
    )
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        conn.execute(
            "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
            " path_template, discovered_by, normaliser_version, first_seen_run)"
            " VALUES('s1','e1','GET','https','app.acme.com',443,'/api/users',"
            "'proxy',1,'NO_SUCH_RUN')"
        )


def test_scope_version_update_rejected(tmp_path: Path):
    """UPDATE on scope_version is blocked by append-only trigger."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e1','acme','Acme',1,'active')"
    )
    conn.execute(
        "INSERT INTO scope_version(id, engagement_id, yaml, sha256, effective_from_us, author)"
        " VALUES('sv1','e1','scope: all','abc123',1000,'admin')"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "UPDATE scope_version SET yaml='scope: modified' WHERE id='sv1'"
        )


def test_scope_version_delete_rejected(tmp_path: Path):
    """DELETE on scope_version is blocked by append-only trigger."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e1','acme','Acme',1,'active')"
    )
    conn.execute(
        "INSERT INTO scope_version(id, engagement_id, yaml, sha256, effective_from_us, author)"
        " VALUES('sv1','e1','scope: all','abc123',1000,'admin')"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "DELETE FROM scope_version WHERE id='sv1'"
        )


# --- I4: finding_status_event/evidence must be append-only under UPDATE and
# DELETE too, and the agent-cannot-confirm rule must hold under UPDATE, not
# just INSERT ---


def _seed_finding(conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e1','acme','Acme',1,'active')"
    )
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES('f1','e1','key1','SQLi','High','Firm','agent','new','insertion')"
    )


def test_finding_status_event_update_rejected(tmp_path: Path):
    """finding_status_event is append-only: UPDATE was previously
    unguarded, letting any row (including one recording an agent's own
    'triaged') be silently rewritten into 'confirmed' after the fact."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    _seed_finding(conn)
    conn.execute(
        "INSERT INTO finding_status_event(id, finding_id, to_status, actor, ts_us)"
        " VALUES('se1','f1','triaged','human',1000)"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "UPDATE finding_status_event SET to_status='confirmed' WHERE id='se1'"
        )


def test_finding_status_event_delete_rejected(tmp_path: Path):
    """finding_status_event is append-only: DELETE was previously
    unguarded, letting a status transition vanish from the audit trail."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    _seed_finding(conn)
    conn.execute(
        "INSERT INTO finding_status_event(id, finding_id, to_status, actor, ts_us)"
        " VALUES('se1','f1','triaged','human',1000)"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM finding_status_event WHERE id='se1'")


def test_agent_cannot_confirm_via_update(tmp_path: Path):
    """The agent-cannot-confirm rule extended to UPDATE: an agent-authored
    row cannot be rewritten into confirmed/reported either. (The blanket
    append-only trigger above also blocks this UPDATE; this proves the
    row-level rule holds independently, in case append-only is ever
    relaxed.)"""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    _seed_finding(conn)
    conn.execute(
        "INSERT INTO finding_status_event(id, finding_id, to_status, actor, ts_us)"
        " VALUES('se1','f1','triaged','agent',1000)"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "UPDATE finding_status_event SET to_status='confirmed' WHERE id='se1'"
        )


def test_human_actor_events_still_insert_with_new_triggers_active(tmp_path: Path):
    """Positive case: legitimate human-actor INSERTs into
    finding_status_event still succeed once the append-only and
    agent-cannot-confirm-update triggers are both in place -- they guard
    UPDATE/DELETE, not INSERT."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    _seed_finding(conn)
    # Must not raise.
    conn.execute(
        "INSERT INTO finding_status_event(id, finding_id, to_status, actor, ts_us)"
        " VALUES('se1','f1','triaged','human',1000)"
    )
    conn.execute(
        "INSERT INTO finding_status_event(id, finding_id, from_status, to_status,"
        " actor, ts_us) VALUES('se2','f1','triaged','confirmed','human',2000)"
    )
    count = conn.execute(
        "SELECT COUNT(*) AS n FROM finding_status_event"
    ).fetchone()["n"]
    assert count == 2


def test_evidence_update_rejected(tmp_path: Path):
    """evidence is immutable: UPDATE was previously unguarded."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    _seed_finding(conn)
    conn.execute(
        "INSERT INTO evidence(id, finding_id, seq, role, kind, captured_us)"
        " VALUES('ev1','f1',1,'primary','response',1000)"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE evidence SET note='tampered' WHERE id='ev1'")


def test_evidence_delete_rejected(tmp_path: Path):
    """evidence is immutable: DELETE was previously unguarded."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    _seed_finding(conn)
    conn.execute(
        "INSERT INTO evidence(id, finding_id, seq, role, kind, captured_us)"
        " VALUES('ev1','f1',1,'primary','response',1000)"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM evidence WHERE id='ev1'")


# --- I5: exactly one engagement row per database ---


def test_engagement_singleton_trigger_rejects_second_row(tmp_path: Path):
    """`quarantine` and every unqualified `open_()` lookup presume a single
    authoritative engagement row. A second INSERT must be rejected, not
    silently accepted."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e1','acme','Acme',1,'active')"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO engagement(id, name, client, created_us, status)"
            " VALUES('e2','globex','Globex',2,'active')"
        )


# --- M8: run.safety_profile has a CHECK, like every other enum column ---


def test_run_safety_profile_invalid_value_rejected(tmp_path: Path):
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e1','acme','Acme',1,'active')"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us, status)"
            " VALUES('r1','e1','manual','yolo',1,'running')"
        )


# --- I7: db.connect must never widen an existing database's permissions,
# and must never let it exist on disk at a looser mode than 0o600 ---


def test_connect_never_widens_a_restricted_database(tmp_path: Path):
    """A database deliberately set to 0o400 must not be healed back to
    writable on open -- that would make `engagement.status = 'sealed'`
    unenforceable at the filesystem level. `connect()` itself does not
    raise (the pragmas it applies -- journal_mode=WAL is already the
    current mode, and synchronous/foreign_keys/busy_timeout are
    per-connection settings, not file writes) so the property is proven two
    ways: the mode on disk is untouched, and an actual write through the
    returned connection genuinely fails."""
    path = tmp_path / "hx.db"
    db.init_schema(db.connect(path))
    path.chmod(0o400)

    conn = db.connect(path)
    assert (path.stat().st_mode & 0o777) == 0o400, "connect() healed permissions back to writable"

    with pytest.raises(sqlite3.OperationalError):
        conn.execute(
            "INSERT INTO engagement(id, name, client, created_us, status)"
            " VALUES('e1','acme','Acme',1,'active')"
        )


def test_connect_tightens_a_loose_existing_database(tmp_path: Path):
    """An existing database at a looser mode (e.g. group/other-readable
    0o644) is tightened to 0o600 on open, not left as-is."""
    path = tmp_path / "hx.db"
    db.init_schema(db.connect(path))
    path.chmod(0o644)
    db.connect(path)
    assert (path.stat().st_mode & 0o777) == 0o600


def test_connect_creates_a_fresh_database_at_0o600(tmp_path: Path):
    """No create-then-chmod window: the database file is created directly
    at its final mode."""
    path = tmp_path / "hx.db"
    db.connect(path)
    assert (path.stat().st_mode & 0o777) == 0o600


# --- New: transaction() groups multi-statement writes atomically ---


def test_transaction_commits_on_success(tmp_path: Path):
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    with db.transaction(conn):
        conn.execute(
            "INSERT INTO engagement(id, name, client, created_us, status)"
            " VALUES('e1','acme','Acme',1,'active')"
        )
    count = conn.execute("SELECT COUNT(*) AS n FROM engagement").fetchone()["n"]
    assert count == 1


def test_transaction_rolls_back_on_exception(tmp_path: Path):
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    with pytest.raises(RuntimeError):
        with db.transaction(conn):
            conn.execute(
                "INSERT INTO engagement(id, name, client, created_us, status)"
                " VALUES('e1','acme','Acme',1,'active')"
            )
            raise RuntimeError("simulated failure mid-transaction")
    count = conn.execute("SELECT COUNT(*) AS n FROM engagement").fetchone()["n"]
    assert count == 0


# --- Task 6: transaction() is reentrant. hx.scan composes two already-atomic
# helpers (`_write_finding`'s own transaction and `records.record_evidence`'s)
# into one, and a bare `BEGIN` inside an open transaction raises
# `OperationalError: cannot start a transaction within a transaction` --
# MEASURED against records.record_evidence before this fix. Both directions
# of the fix are pinned below rather than only the happy path, per the
# ruling that a savepoint path swallowing a rollback would be worse than the
# bug it replaces. ---


def test_nested_transaction_inner_failure_rolls_back_only_inner_and_propagates(
    tmp_path: Path,
):
    """A nested `transaction()` call that raises undoes ONLY its own writes
    -- via SAVEPOINT / ROLLBACK TO SAVEPOINT, not the outer BEGIN -- and the
    exception still propagates out of the inner `with` block rather than
    being swallowed. The outer transaction is left alive and can go on to
    commit its own writes, proving the inner failure did not also doom it."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    with db.transaction(conn):
        conn.execute(
            "INSERT INTO engagement(id, name, client, created_us, status)"
            " VALUES('e1','acme','Acme',1,'active')"
        )
        with pytest.raises(RuntimeError, match="inner failure"):
            with db.transaction(conn):
                conn.execute(
                    "INSERT INTO run(id, engagement_id, kind, safety_profile,"
                    " started_us, status)"
                    " VALUES('r1','e1','manual','production',1,'running')"
                )
                raise RuntimeError("inner failure")
        # The outer transaction is still open: MEASURED by writing again and
        # letting it commit, rather than assumed.
        conn.execute(
            "INSERT INTO run(id, engagement_id, kind, safety_profile,"
            " started_us, status)"
            " VALUES('r2','e1','manual','production',2,'running')"
        )
    assert conn.execute("SELECT COUNT(*) FROM engagement").fetchone()[0] == 1
    # r1 (the failed nested INSERT) is gone; r2 (written after, inside the
    # still-live outer transaction) survived.
    assert [r[0] for r in conn.execute("SELECT id FROM run ORDER BY id")] == ["r2"]

    # The savepoint stack was left clean, not wedged: an unrelated LATER
    # transaction on the same connection still commits normally rather than
    # erroring on a dangling SAVEPOINT name or an unbalanced RELEASE.
    with db.transaction(conn):
        conn.execute(
            "INSERT INTO run(id, engagement_id, kind, safety_profile,"
            " started_us, status)"
            " VALUES('r3','e1','manual','production',3,'running')"
        )
    assert conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 2


def test_nested_transaction_outer_failure_rolls_back_everything(tmp_path: Path):
    """RELEASING a savepoint is not committing: SQLite only durably commits
    at the outermost COMMIT, so a nested `transaction()` that succeeds and
    releases cleanly is only provisionally applied. If the OUTER block later
    fails, its ROLLBACK must undo the released inner work too -- a savepoint
    path that let committed-looking inner work survive an outer rollback
    would make a partial write look atomic, which is worse than the bug this
    replaces."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    with pytest.raises(RuntimeError, match="outer failure"):
        with db.transaction(conn):
            conn.execute(
                "INSERT INTO engagement(id, name, client, created_us, status)"
                " VALUES('e1','acme','Acme',1,'active')"
            )
            with db.transaction(conn):
                conn.execute(
                    "INSERT INTO run(id, engagement_id, kind, safety_profile,"
                    " started_us, status)"
                    " VALUES('r1','e1','manual','production',1,'running')"
                )
            # The nested transaction above released cleanly. It must not
            # have escaped the outer transaction's authority regardless.
            raise RuntimeError("outer failure")
    assert conn.execute("SELECT COUNT(*) FROM engagement").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 0


# --- Fix round 1, F5: nesting must be tracked explicitly, not inferred from
# `conn.in_transaction` -- that flag cannot distinguish an outer
# `transaction()` call from sqlite3's own driver-implicit BEGIN. ---


def test_transaction_fails_loudly_rather_than_losing_data_on_a_driver_implicit_transaction(
    tmp_path: Path,
):
    """F5 of the task-6 review. Deliberately NOT `db.connect()`, which always
    passes `isolation_level=None` -- this is sqlite3's own DEFAULT isolation
    mode, which auto-opens a transaction before the first DML statement.

    Under the OLD (`conn.in_transaction`-based) implementation this is
    exactly the failure: `conn.in_transaction` is already `True` from the
    driver's own implicit BEGIN, so `transaction()` mistook it for nesting,
    took the SAVEPOINT path, and RELEASEd without ever COMMITting -- the
    INSERT below would survive the `with` block in memory but vanish on
    close, silently. MEASURED before this fix: the row was gone from a fresh
    connection to the same file, no exception anywhere.

    Tracking nesting with `db._OPEN_TRANSACTIONS` (keyed by `id(conn)`,
    populated only by `transaction()` itself) instead means this connection's
    id was never added by us, so `transaction()` takes the OUTERMOST path --
    and a `BEGIN` against a connection sqlite3 already opened one on fails
    LOUDLY, exactly as it did before Task 6 existed.
    """
    path = tmp_path / "hx.db"
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA foreign_keys=ON")
    db.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e1','acme','Acme',1,'active')"
    )
    assert conn.in_transaction, "the driver's own implicit BEGIN, not ours"

    with pytest.raises(sqlite3.OperationalError, match="transaction"):
        with db.transaction(conn):
            conn.execute(
                "INSERT INTO run(id, engagement_id, kind, safety_profile,"
                " started_us, status)"
                " VALUES('r1','e1','manual','production',1,'running')"
            )
    conn.rollback()
    conn.close()

    # Nothing was silently lost OR silently kept: the whole implicit
    # transaction -- including the engagement row that predated the failed
    # `transaction()` call -- rolled back, because sqlite3 refused to let it
    # proceed at all. A fresh connection to the same file sees neither row.
    reread = sqlite3.connect(str(path))
    assert reread.execute("SELECT COUNT(*) FROM engagement").fetchone()[0] == 0
    assert reread.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 0
    reread.close()
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_db.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.store.db'`

- [ ] **Step 4: Write the schema**

```sql
-- src/hx/store/schema.sql
-- All timestamps are integer microseconds since epoch.

CREATE TABLE IF NOT EXISTS engagement (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  client       TEXT NOT NULL,
  created_us   INTEGER NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('active','sealed','archived')),
  config_path  TEXT
);

-- Exactly one engagement per database: the engagement is the unit of
-- isolation (spec S3), and `quarantine` and every unqualified `open_()`
-- lookup presume a single authoritative row. Without this, a second INSERT
-- is accepted silently and which client the store believes it holds becomes
-- arbitrary.
CREATE TRIGGER IF NOT EXISTS trg_engagement_singleton
BEFORE INSERT ON engagement
WHEN (SELECT COUNT(*) FROM engagement) > 0
BEGIN
  SELECT RAISE(ABORT, 'only one engagement row is permitted per database');
END;

-- Append-only. Never UPDATE a row here: "what was in scope when request X was
-- issued" is the query that matters under dispute.
CREATE TABLE IF NOT EXISTS scope_version (
  id                TEXT PRIMARY KEY,
  engagement_id     TEXT NOT NULL REFERENCES engagement(id),
  yaml              TEXT NOT NULL,
  sha256            TEXT NOT NULL,
  effective_from_us INTEGER NOT NULL,
  author            TEXT NOT NULL,
  reason            TEXT
);

CREATE TABLE IF NOT EXISTS authorization (
  id            TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL REFERENCES engagement(id),
  doc_blob      TEXT,
  doc_sha256    TEXT,
  signatory     TEXT,
  valid_from_us INTEGER,
  valid_to_us   INTEGER,
  scope_sha256  TEXT
);

CREATE TABLE IF NOT EXISTS run (
  id               TEXT PRIMARY KEY,
  engagement_id    TEXT NOT NULL REFERENCES engagement(id),
  -- Amended 2026-08-24 with SCHEMA_VERSION 4. S5's vocabulary is
  -- browse | crawl | manual | scan, and this CHECK still named
  -- ('manual','scheduled','retest') -- values from before the proxy existed.
  -- The spec text was amended for Plan 4 and the constraint was not, which is
  -- exactly the drift the spec amendment itself warns about: a spec that
  -- disagrees with its implementation stops being consulted. Found by Task 3
  -- refusing to start rather than working around it.
  kind             TEXT NOT NULL CHECK (kind IN ('browse','crawl','manual','scan')),
  safety_profile   TEXT NOT NULL CHECK (safety_profile IN ('production','staging')),
  scope_version_id TEXT REFERENCES scope_version(id),
  started_us       INTEGER NOT NULL,
  ended_us         INTEGER,
  status           TEXT NOT NULL
                   CHECK (status IN ('running','completed','aborted','killed','error')),
  stop_reason      TEXT,
  heartbeat_us     INTEGER,
  requests_issued  INTEGER NOT NULL DEFAULT 0,
  dropped_total    INTEGER NOT NULL DEFAULT 0,
  -- WHICH IDENTITY THIS RUN ISSUED ITS OWN REQUESTS UNDER, and what the
  -- bracketed liveness window settled at. Added 2026-08-30 with
  -- SCHEMA_VERSION 9. All three are NULL for a run that issued anonymously,
  -- which is every `browse` run (the operator's own browser carries its own
  -- session; the identity design's s2 puts proxy traffic out of scope) and
  -- every scan whose config names no `scan_identity`.
  --
  -- THE SAME THREE NAMES `exchange` ALREADY CARRIES, deliberately. That
  -- section-6 triple is where the state belongs per request, and the same
  -- section's 2026-08-30 amendment records why it cannot be written yet:
  -- `Capture.java` delivers `via: proxy` and nothing else, so this build
  -- stores no send-path exchange row at all. What section 9's retirement
  -- gate actually needs is narrower -- whether the run's traffic was issued
  -- inside a proven window -- and that is a run-level fact. Spelling it the
  -- same way here means the day send-path recording lands, the per-exchange
  -- column is a refinement of this one rather than a second vocabulary.
  --
  -- `identity_state` COLLAPSES TO THE WORST WINDOW IN THE RUN
  -- (`hx.identity.IdentityWindow`): one failed canary anywhere makes the
  -- whole run `assumed`, so a run that reads `proven` had every window in it
  -- proven. `hx.scan.run` also refuses to write `proven` for a run that
  -- stopped short, because a window is proof only once BOTH its canaries
  -- have passed and a halted run never ran its closing one.
  identity            TEXT,
  identity_generation INTEGER,
  identity_state      TEXT CHECK (identity_state IN ('proven','assumed','dead'))
);

-- Surface identity is the TEMPLATE. /order/1..9999 is one surface, not 9999.
CREATE TABLE IF NOT EXISTS surface (
  id                  TEXT PRIMARY KEY,
  engagement_id       TEXT NOT NULL REFERENCES engagement(id),
  method              TEXT NOT NULL,
  scheme              TEXT NOT NULL,
  host                TEXT NOT NULL,
  port                INTEGER NOT NULL,
  path_template       TEXT NOT NULL,
  query_key_set       TEXT NOT NULL DEFAULT '',
  kind                TEXT NOT NULL DEFAULT 'unknown'
                      CHECK (kind IN ('idempotent_read','state_changing','unknown')),
  -- NO DEFAULT, amended 2026-08-25 with SCHEMA_VERSION 6, on the same
  -- argument `normaliser_version` lost its own and `denial.via` was never
  -- given one. This column answers "which egress point found this surface",
  -- and S5 draws a coverage figure straight off it -- "crawl-discovered
  -- surfaces are recorded with discovered_by = 'crawl'". DEFAULT 'proxy'
  -- answered that question for any writer who did not ask it, so every
  -- crawler-discovered surface would have been labelled `proxy` with nothing
  -- to tell afterwards. An omission must fail loudly instead.
  discovered_by       TEXT NOT NULL
                      CHECK (discovered_by IN ('proxy','crawl','import','agent')),
  -- NO DEFAULT, amended 2026-08-24. This column answers "which ruleset
  -- produced this row", and a default answers it with a guess. It read
  -- DEFAULT 1 while the ruleset moved to 2 in Plan 4's Task 2, so an insert
  -- omitting it would have stamped rows with a ruleset that no longer exists
  -- and nothing could tell afterwards. An omission must fail loudly instead.
  normaliser_version  INTEGER NOT NULL,
  first_seen_run      TEXT REFERENCES run(id),
  last_seen_run       TEXT REFERENCES run(id),
  exemplar_exchange_id TEXT REFERENCES exchange(id),
  UNIQUE (engagement_id, method, scheme, host, port, path_template, query_key_set)
);

CREATE TABLE IF NOT EXISTS exchange (
  id                  TEXT PRIMARY KEY,
  run_id              TEXT REFERENCES run(id),
  surface_id          TEXT REFERENCES surface(id),
  action_id           TEXT,
  identity            TEXT,
  identity_generation INTEGER,
  identity_state      TEXT CHECK (identity_state IN ('proven','assumed','dead')),
  via                 TEXT NOT NULL CHECK (via IN ('proxy','send','crawl')),
  outcome             TEXT NOT NULL
                      CHECK (outcome IN ('ok','timeout','conn_refused','dns_error',
                                         'tls_error','scope_denied','rate_limited',
                                         'bridge_lost','truncated',
                                         -- The exchange COMPLETED but its final
                                         -- status could not be read: a peer put
                                         -- more interim 1xx heads in front of the
                                         -- response than the scan tolerates.
                                         -- `status` then holds the conservative
                                         -- sentinel 599, so this value is the only
                                         -- thing separating that sentinel from a
                                         -- peer that genuinely answered 599.
                                         'status_unreadable')),
  sent_us             INTEGER NOT NULL,
  recv_us             INTEGER,
  method              TEXT NOT NULL,
  url                 TEXT NOT NULL,
  resolved_ip         TEXT,
  status              INTEGER,
  req_blob            TEXT,
  resp_blob           TEXT,
  resp_len            INTEGER,
  body_shed           INTEGER NOT NULL DEFAULT 0,
  scope_version_id    TEXT REFERENCES scope_version(id),
  seq                 INTEGER
);
CREATE INDEX IF NOT EXISTS idx_exchange_run  ON exchange(run_id, seq);
CREATE INDEX IF NOT EXISTS idx_exchange_surf ON exchange(surface_id);

-- Records that a check RAN. Without this, "tested clean", "never reached",
-- "blocked" and "errored" are indistinguishable and reports lie.
CREATE TABLE IF NOT EXISTS check_run (
  id             TEXT PRIMARY KEY,
  run_id         TEXT NOT NULL REFERENCES run(id),
  surface_id     TEXT REFERENCES surface(id),
  insertion_name TEXT,
  check_id       TEXT NOT NULL,
  check_version  TEXT NOT NULL,
  started_us     INTEGER,
  ended_us       INTEGER,
  verdict        TEXT NOT NULL
                 CHECK (verdict IN ('pending','clean','finding','inconclusive',
                                    'skipped','error')),
  reason         TEXT,
  requests_sent  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_checkrun_run ON check_run(run_id, verdict);

CREATE TABLE IF NOT EXISTS finding (
  id                 TEXT PRIMARY KEY,
  engagement_id      TEXT NOT NULL REFERENCES engagement(id),
  dedupe_key         TEXT NOT NULL,
  -- TWO DIFFERENT AXES, added at two different times, and the collision
  -- between them is exactly the thing this comment exists to foreclose.
  --
  -- issue_type_id: WHAT KIND OF ISSUE THIS IS. Spec S10/S12: report text,
  -- severity and CWE mappings come from Burp's 183 vendored issue
  -- definitions, so a report reads in the same vocabulary a Pro user's
  -- would. Adopting those ids is still a later plan's job; until then each
  -- check names its own stable value -- lowercase kebab (`missing-hsts`)
  -- unless the id has to carry a name the protocol treats as case-sensitive,
  -- as `cookie_flags` does for the cookie -- and swapping in Burp's
  -- vocabulary later is a change of SPELLING on this axis, not a change of
  -- what the axis means. NOT to be used for anything
  -- else, including the column immediately below.
  --
  -- WRITTEN, and part of identity, since F1 of the whole-branch review
  -- (HIGH). It is the 2nd part of `finding.dedupe_key` (see
  -- `records.dedupe_key`), because every other part of that key is fixed by
  -- the check and the surface: without it, three security headers missing
  -- from one response filed ONE finding wearing the first candidate's title
  -- and the last candidate's severity. This column being DECLARED AND
  -- UNWRITTEN is also what made it look like a free slot to the earlier fix
  -- described below; it is neither free nor unwritten now.
  --
  -- check_id: WHICH hx CHECK FOUND THIS, added at SCHEMA_VERSION 7 (fix
  -- round 2 of Task 6). `hx.scan._mark_unobserved` needs to know, for a
  -- retest, whether the SAME check that produced a finding ran clean on the
  -- SAME surface again this run -- surface alone was measured to mark a
  -- finding "observed=0" (which a report renders as FIXED) even when the
  -- check that owns it crashed, went inconclusive, or never ran this run at
  -- all (F1 of the task-6 review, HIGH). `issue_type_id` briefly carried
  -- `check.id` for this purpose between fix rounds 1 and 2 -- WRONG, because
  -- it collides with the axis above the day a later plan starts writing
  -- real Burp issue-type ids here, with nothing at the schema level to catch
  -- the two fighting over one column. This column is that catch.
  issue_type_id      TEXT,
  check_id           TEXT,
  title              TEXT NOT NULL,
  description        TEXT,
  impact             TEXT,
  remediation        TEXT,
  cwe                TEXT,
  references_json    TEXT,
  severity           TEXT NOT NULL
                     CHECK (severity IN ('Critical','High','Medium','Low','Info')),
  severity_source    TEXT,
  confidence         TEXT NOT NULL CHECK (confidence IN ('Certain','Firm','Tentative')),
  created_by         TEXT NOT NULL CHECK (created_by IN ('agent','human','check')),
  -- Cached projection of finding_status_event, the source of truth. Direct
  -- `UPDATE finding SET status=...` is deliberately left unguarded here --
  -- unlike the event log, this column is a read-optimisation, not the
  -- record of who changed what and when.
  status             TEXT NOT NULL
                     CHECK (status IN ('new','triaged','confirmed','false_positive','reported')),
  surface_id         TEXT REFERENCES surface(id),
  insertion_name     TEXT,
  insertion_kind     TEXT,
  host               TEXT,
  scope_level        TEXT NOT NULL
                     CHECK (scope_level IN ('engagement','host','surface','insertion')),
  payload            TEXT,
  -- Still DEFAULT 1, and it is WRONG now rather than premature. The same
  -- argument as surface.normaliser_version applies -- a column answering
  -- "which ruleset produced this row" should not answer it with a guess --
  -- and the deadline the previous version of this comment set for itself
  -- ("nothing produces a finding until Plan 6, so the default is not yet
  -- WRONG here, only premature") has passed. Plan 5, checks-and-reporting,
  -- was the plan that first wrote a finding, and it is merged: every finding
  -- row now carries 1 while hx.surface.NORMALISER_VERSION is 2.
  --
  -- Deferred rather than urgent because it is wrong in a column no reader
  -- consults: nothing in Python writes it (records.upsert_finding's column
  -- list omits it) and nothing reads it -- no report section, no retest
  -- path, no query. Removing the default costs 11 fixture rewrites in a
  -- merged plan's test file. Whoever takes it takes this comment with it.
  normaliser_version INTEGER NOT NULL DEFAULT 1,
  first_seen_run     TEXT REFERENCES run(id),
  last_seen_run      TEXT REFERENCES run(id),
  UNIQUE (engagement_id, dedupe_key)
);

-- Presence per run as a SET, not a range: found in run 3, fixed in run 5,
-- reintroduced in run 7 must be expressible. That is the retest deliverable.
CREATE TABLE IF NOT EXISTS finding_observation (
  finding_id    TEXT NOT NULL REFERENCES finding(id),
  run_id        TEXT NOT NULL REFERENCES run(id),
  observed      INTEGER NOT NULL,
  exchange_id   TEXT REFERENCES exchange(id),
  severity_at   TEXT,
  confidence_at TEXT,
  ts_us         INTEGER NOT NULL,
  PRIMARY KEY (finding_id, run_id)
);

CREATE TABLE IF NOT EXISTS finding_status_event (
  id          TEXT PRIMARY KEY,
  finding_id  TEXT NOT NULL REFERENCES finding(id),
  from_status TEXT,
  to_status   TEXT NOT NULL
               CHECK (to_status IN ('new','triaged','confirmed','false_positive','reported')),
  actor       TEXT NOT NULL CHECK (actor IN ('agent','human','check')),
  note        TEXT,
  ts_us       INTEGER NOT NULL
);

-- The agent may never confirm its own finding. Enforced by the database,
-- not by discipline. Covers both the initial INSERT and any later UPDATE
-- that tries to rewrite an existing event row into a confirmed/reported one
-- -- an UPDATE bypassed the INSERT-only version of this trigger entirely.
CREATE TRIGGER IF NOT EXISTS trg_agent_cannot_confirm
BEFORE INSERT ON finding_status_event
WHEN NEW.actor = 'agent' AND NEW.to_status IN ('confirmed','reported')
BEGIN
  SELECT RAISE(ABORT, 'agent may not set status confirmed or reported');
END;

CREATE TRIGGER IF NOT EXISTS trg_agent_cannot_confirm_update
BEFORE UPDATE ON finding_status_event
WHEN NEW.actor = 'agent' AND NEW.to_status IN ('confirmed','reported')
BEGIN
  SELECT RAISE(ABORT, 'agent may not set status confirmed or reported');
END;

-- scope_version is append-only: tamper-evidence for contract disputes.
CREATE TRIGGER IF NOT EXISTS trg_scope_version_no_update
BEFORE UPDATE ON scope_version
BEGIN
  SELECT RAISE(ABORT, 'scope_version is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_scope_version_no_delete
BEFORE DELETE ON scope_version
BEGIN
  SELECT RAISE(ABORT, 'scope_version is append-only');
END;

-- finding_status_event is append-only, same rationale as scope_version: it
-- is the audit trail of who changed a finding's status and when. An UPDATE
-- or DELETE here would let a status transition be silently rewritten after
-- the fact, including one that used to launder an agent-confirmed status
-- through a legitimate human INSERT and then UPDATE it back.
CREATE TRIGGER IF NOT EXISTS trg_finding_status_event_no_update
BEFORE UPDATE ON finding_status_event
BEGIN
  SELECT RAISE(ABORT, 'finding_status_event is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_finding_status_event_no_delete
BEFORE DELETE ON finding_status_event
BEGIN
  SELECT RAISE(ABORT, 'finding_status_event is append-only');
END;

CREATE TABLE IF NOT EXISTS evidence (
  id          TEXT PRIMARY KEY,
  finding_id  TEXT NOT NULL REFERENCES finding(id),
  seq         INTEGER NOT NULL,
  role        TEXT NOT NULL,
  kind        TEXT NOT NULL,
  exchange_id TEXT REFERENCES exchange(id),
  ref         TEXT,
  note        TEXT,
  captured_us INTEGER NOT NULL
);

-- Immutable, same rationale as finding_status_event: evidence is what a
-- disputed finding is proven with, and it must not be alterable after
-- capture.
CREATE TRIGGER IF NOT EXISTS trg_evidence_no_update
BEFORE UPDATE ON evidence
BEGIN
  SELECT RAISE(ABORT, 'evidence is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_evidence_no_delete
BEFORE DELETE ON evidence
BEGIN
  SELECT RAISE(ABORT, 'evidence is immutable');
END;

CREATE TABLE IF NOT EXISTS agent_action (
  id             TEXT PRIMARY KEY,
  engagement_id  TEXT NOT NULL REFERENCES engagement(id),
  run_id         TEXT REFERENCES run(id),
  ts_us          INTEGER NOT NULL,
  actor          TEXT NOT NULL,
  tool           TEXT NOT NULL,
  args_blob      TEXT,
  result_summary TEXT,
  why            TEXT
);
CREATE INDEX IF NOT EXISTS idx_action_run ON agent_action(run_id, ts_us);

CREATE TABLE IF NOT EXISTS denial (
  id               TEXT PRIMARY KEY,
  run_id           TEXT REFERENCES run(id),
  ts_us            INTEGER NOT NULL,
  -- `credential` added 2026-08-25 with SCHEMA_VERSION 6. S4 is
  -- unconditional -- "Any denial produces a `denial` row and a distinct error
  -- class. Denials are never silent" -- and `unmanaged_credential` was a
  -- denial this vocabulary had no value for, so it reached the proxy's egress
  -- point and vanished: no row, no counter, no exception. S7 refuses the
  -- request and never persists it; that is a fact about the REQUEST BYTES,
  -- and it never meant the refusal itself goes unrecorded. The row carries
  -- method, url and a reason, never the credential.
  kind             TEXT NOT NULL
                   CHECK (kind IN ('scope','method','dangerous','rate','budget',
                                   'not_configured','credential')),
  method           TEXT,
  url              TEXT,
  resolved_ip      TEXT,
  reason           TEXT,
  -- Added 2026-08-25 with SCHEMA_VERSION 5. `exchange` has carried `via`
  -- since Plan 1 and `denial` never did, which cost nothing while `send` was
  -- the only value either could hold. Plan 4 makes the proxy a second egress
  -- point, and `SELECT kind, COUNT(*) FROM denial` would then answer for two
  -- at once with no way to tell them apart -- so "the crawler is being
  -- refused everywhere" and "my browsing is being refused everywhere" become
  -- one number, and they are opposite instructions.
  --
  -- The same three values as exchange.via, deliberately: a fourth would mean
  -- a fourth egress path, which S4 forbids outright. NOT NULL with no
  -- DEFAULT, for the reason surface.normaliser_version lost its own.
  -- `records.record_denial` does default the PARAMETER to 'send', which is a
  -- documented fact about which callers exist; a DEFAULT here would be a
  -- different thing -- the answer a raw INSERT gets without being asked, and
  -- a raw INSERT is exactly the shape a future writer takes.
  via              TEXT NOT NULL CHECK (via IN ('proxy','send','crawl')),
  scope_version_id TEXT REFERENCES scope_version(id)
);

-- Inbound traffic that did not match this engagement. Never silently
-- discarded, never allowed into `exchange`.
CREATE TABLE IF NOT EXISTS quarantine (
  id                    TEXT PRIMARY KEY,
  received_us           INTEGER NOT NULL,
  engagement_id_claimed TEXT,
  method                TEXT,
  url                   TEXT,
  reason                TEXT NOT NULL,
  raw_blob              TEXT
);
```

- [ ] **Step 5: Write the minimal implementation**

```python
# src/hx/store/db.py
"""SQLite access for one engagement.

Every connection must apply the same pragmas. foreign_keys in particular is
OFF per-connection by default in SQLite, so a connection opened without it
silently ignores every REFERENCES clause in the schema.
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from contextlib import contextmanager
from importlib import resources
from pathlib import Path

from hx.store.paths import secure_mkdir

# 5 -> 6 (2026-08-25): `denial.kind` gained 'credential' and
# `surface.discovered_by` lost its DEFAULT. Both land inside Plan 4's branch,
# on top of the 4 -> 5 bump that added `denial.via` a commit earlier -- and
# reusing 5 for them would have made two INCOMPATIBLE schemas share one
# version number, since a database created at that earlier commit already
# exists on disk. Such a file refuses every `credential` denial this code now
# writes: its CHECK has no such value, so SQLite rejects the INSERT. It also
# still answers 'proxy' for any writer that omits `surface.discovered_by`
# rather than failing, which is the guess the DEFAULT was removed to stop.
# `engagement.open_`'s comparison against this constant is the only thing in
# the tree that can notice either.
#
# 6 -> 7 (2026-08-27, Task 6 fix round 2): `finding` gained `check_id`,
# additive and nullable -- no existing row's meaning changes, so this bump
# exists only to make an old store's absence of the column loud
# (`engagement.open_`'s version check) rather than something a later reader
# discovers by getting a `sqlite3.OperationalError: no such column` from a
# query it had every right to assume would work. See schema.sql's own
# comment on `finding.check_id` for why the column exists: it is NOT the
# same axis as `finding.issue_type_id`, and conflating the two was reachable
# without one.
# 7 -> 8 (2026-08-27, whole-branch review fix round A): NO DDL CHANGE, and
# the bump is deliberate anyway. `finding.dedupe_key`'s FORMAT changed --
# `records.dedupe_key` gained `issue_type_id` as its 2nd part (F1, HIGH),
# and blanks `method`/`path_template` for a host-scoped finding and the
# whole location for an engagement-scoped one (F3, MEDIUM) --
# so every key an older store holds is spelled in a format this code will
# never produce again. Nothing would fail: the UNIQUE constraint is on the
# string, so the first scan against such a store simply re-files every
# finding it already holds as new, with `first_seen_run` reset and the
# operator's triage stranded on the old row. That is precisely the silent
# outcome the 6 -> 7 comment above says this constant exists to make loud,
# and "the column list did not change" is not the test -- whether an older
# file still MEANS what this code assumes is. `engagement.open_`'s version
# check is the only thing in the tree that can notice.
#
# 8 -> 9 (2026-08-30, identity Task 8): `run` gained `identity`,
# `identity_generation` and `identity_state`, additive and nullable. As with
# 6 -> 7 no existing row's meaning changes, and the bump exists to make an
# older store's absence of the columns loud rather than a
# `sqlite3.OperationalError` out of a query with every right to expect them:
# `hx.report._limits` and the report's identity section now READ
# `run.identity_state`, and `hx.scan.run` writes it on every path a run can
# end by. A store written before this commit answers NULL for a scan that did
# issue under a proved session -- which renders as the anonymous case, the
# safe direction, but says something false about that run. Refusing to open
# it is the loud version of the same fact.
SCHEMA_VERSION = 9

TABLES: tuple[str, ...] = (
    "engagement",
    "scope_version",
    "authorization",
    "run",
    "surface",
    "exchange",
    "check_run",
    "finding",
    "finding_observation",
    "finding_status_event",
    "evidence",
    "agent_action",
    "denial",
    "quarantine",
)


def connect(path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    path = Path(path)
    if readonly:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    else:
        secure_mkdir(path.parent)
        if not path.exists():
            # Pre-create at the final mode so the database file never exists
            # on disk at a looser permission than 0o600, even for an
            # instant -- the create-then-chmod window this closes is the
            # same class of bug fixed for config.yaml.
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        else:
            # Only ever TIGHTEN an existing file's permissions, never widen
            # them. `path.chmod(0o600)` unconditionally healed a
            # deliberately-restricted file (e.g. 0o400 on a sealed
            # engagement) back to writable on every open -- making
            # `engagement.status = 'sealed'` unenforceable at the
            # filesystem level.
            mode = path.stat().st_mode & 0o777
            if mode & 0o077:
                path.chmod(mode & 0o700)
        conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    if not readonly:
        # journal_mode is a write to the database header, so it raises
        # OperationalError on a read-only connection. The mode is a property
        # of the file, already set by the writer, so readers inherit it.
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _schema_sql() -> str:
    return resources.files("hx.store").joinpath("schema.sql").read_text(encoding="utf-8")


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_schema_sql())
    conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")


# Connections `transaction()` currently owns the OUTER `BEGIN` for, tracked
# by `id(conn)` rather than as an attribute ON the connection -- MEASURED:
# `sqlite3.Connection` (and a bare subclass of it) refuses arbitrary
# attribute assignment (`AttributeError: 'sqlite3.Connection' object has no
# attribute ...`) and is not weak-referenceable either, so there is no
# per-object place on the connection itself to record this. `id()`-keying is
# safe against id-reuse specifically because the only code that ever inserts
# a key also removes it, in a `finally`, before returning -- and for the
# whole of that window the caller holds a live reference to `conn` on the
# stack (it is the function's own argument), so the object cannot be
# garbage-collected and its id() handed to something else while the key is
# live. See F5 of the task-6 review for why this exists at all: `db.py`'s
# previous version asked `conn.in_transaction`, which cannot distinguish an
# OUTER `transaction()` call from sqlite3's own driver-implicit `BEGIN` (any
# connection not opened with `isolation_level=None` opens one before its
# first DML statement) -- and on such a connection, MEASURED, the old code
# took the SAVEPOINT path, `RELEASE`d, and never `COMMIT`ted: a loud
# `OperationalError` became silent data loss.
_OPEN_TRANSACTIONS: set[int] = set()


@contextmanager
def transaction(conn: sqlite3.Connection):
    """Group statements into one all-or-nothing unit.

    Connections from `connect()` are autocommit (isolation_level=None), so
    any multi-statement write that is not wrapped in an explicit
    BEGIN/COMMIT is not atomic -- a failure partway through leaves whatever
    already ran committed. Exactly one place in this codebase remembered
    that on its own before this helper existed; more call sites were expected
    in later plans, and this is cheap insurance against one of them
    forgetting. `hx.capture.on_exchange` is the first of those and did forget
    -- it wrote four statements unwrapped, and `upsert_surface` failing left a
    committed exchange row with a NULL `surface_id` behind it.

    REENTRANT, since Task 6. `conn.execute("BEGIN")` against a connection
    already inside a transaction raises
    `OperationalError: cannot start a transaction within a transaction` --
    MEASURED, the first time `hx.scan.run` called `records.record_evidence`
    (which wraps itself in `transaction(conn)`) from inside its own
    `_write_finding`, itself wrapped in `transaction(conn)`. A caller
    composing two already-atomic helpers into one atomic unit is exactly the
    "more call sites... in later plans" this docstring already predicted, so
    the helper -- not either call site -- is what learns to nest.

    WHICH PATH RUNS IS DECIDED BY OUR OWN `_OPEN_TRANSACTIONS` MARKER, NEVER
    BY `conn.in_transaction`. That flag reflects the DRIVER's state, not
    OURS, and the two are different questions: it is true both when this
    function opened the transaction and when sqlite3's own default isolation
    mode auto-began one behind our back, and `transaction()` needs to answer
    only the first. Outermost (this connection's id not in the marker set):
    a plain `BEGIN`/`COMMIT`/`ROLLBACK`, unchanged from before -- MEASURED
    against `hx.capture.on_exchange`, the merged, reviewed, non-nested
    caller, whose own tests (`tests/test_capture.py`) still pass unmodified.
    Nested (this connection's id already in the marker set, because an outer
    `transaction()` call is still on the stack): a named `SAVEPOINT`,
    released on success or rolled back to (then released) on failure, before
    re-raising -- so an inner failure undoes only the inner block's writes
    and the exception still propagates, while the OUTER transaction is left
    exactly as if the inner block had never run, free to retry or to fail on
    its own account.

    A connection that never goes through an outer `transaction()` call at
    all -- one where sqlite3's own driver opened an implicit transaction on
    its own -- is never in the marker set, so it always takes the OUTERMOST
    path here and gets the loud `OperationalError` a doubled `BEGIN`
    produces, exactly as before this function existed. That is deliberate:
    see F5 above for what happened when nesting was instead inferred from
    `conn.in_transaction`.

    RELEASING A SAVEPOINT IS NOT COMMITTING. SQLite only durably commits at
    the outermost `COMMIT` -- a `RELEASE` just folds the inner block's writes
    into the still-open outer transaction, so if the OUTER block later fails,
    its `ROLLBACK` undoes the released inner work too, not just what the
    outer block wrote itself. MEASURED both directions below (both are pinned
    in `tests/test_db.py`):

      * inner raises: the inner INSERT is gone, the exception propagates, and
        a SEPARATE inner transaction run afterwards on the same connection
        commits normally -- the savepoint stack was left clean, not wedged.
      * outer raises, after a nested transaction already ran and released
        cleanly inside it: the inner block's INSERT is ALSO gone. A savepoint
        path that let it survive would make a partial write look atomic,
        which is worse than the bug this replaces.
    """
    key = id(conn)
    if key not in _OPEN_TRANSACTIONS:
        _OPEN_TRANSACTIONS.add(key)
        try:
            conn.execute("BEGIN")
            try:
                yield conn
            except BaseException:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass  # transaction already gone; do not mask the original error
                raise
            else:
                conn.execute("COMMIT")
        finally:
            _OPEN_TRANSACTIONS.discard(key)
        return

    name = f"sp_{uuid.uuid4().hex}"
    conn.execute(f"SAVEPOINT {name}")
    try:
        yield conn
    except BaseException:
        try:
            conn.execute(f"ROLLBACK TO SAVEPOINT {name}")
            conn.execute(f"RELEASE SAVEPOINT {name}")
        except sqlite3.Error:
            pass  # savepoint already gone; do not mask the original error
        raise
    else:
        conn.execute(f"RELEASE SAVEPOINT {name}")
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_db.py -v`
Expected: PASS, 6 passed

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml src/hx tests/test_db.py
git commit -m "feat(store): engagement schema with enforced FKs and agent-cannot-confirm trigger"
```

---

### Task 2: Content-addressed blob store

**Files:**
- Create: `src/hx/store/blobs.py`
- Test: `tests/test_blobs.py`

**Interfaces:**
- Consumes: nothing from Task 1
- Produces:
  - `hx.store.blobs.BlobStore(root: Path)`
  - `BlobStore.put(data: bytes) -> tuple[str, int]` — returns `(sha256_hex, length)`
  - `BlobStore.get(digest: str, expected_len: int | None = None) -> bytes`
  - `BlobStore.path_for(digest: str) -> Path`
  - `hx.store.blobs.CorruptBlob(Exception)`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_blobs.py
from pathlib import Path

import pytest

from hx.store.blobs import BlobStore, CorruptBlob


def test_put_then_get_round_trips(tmp_path: Path):
    store = BlobStore(tmp_path)
    digest, length = store.put(b"hello burp")
    assert length == 10
    assert store.get(digest) == b"hello burp"


def test_identical_content_stored_once(tmp_path: Path):
    store = BlobStore(tmp_path)
    d1, _ = store.put(b"same bytes")
    d2, _ = store.put(b"same bytes")
    assert d1 == d2
    assert sum(1 for p in tmp_path.rglob("*") if p.is_file()) == 1


def test_get_verifies_length(tmp_path: Path):
    store = BlobStore(tmp_path)
    digest, length = store.put(b"abcdef")
    with pytest.raises(CorruptBlob):
        store.get(digest, expected_len=999)


def test_truncated_blob_on_disk_is_detected(tmp_path: Path):
    """A torn write must fail loudly, not poison every future identical body."""
    store = BlobStore(tmp_path)
    digest, _ = store.put(b"a" * 500)
    store.path_for(digest).write_bytes(b"a" * 200)
    with pytest.raises(CorruptBlob):
        store.get(digest)


def test_large_blob_round_trips(tmp_path: Path):
    store = BlobStore(tmp_path)
    payload = bytes(range(256)) * 8000  # ~2 MB, larger than a Burp response
    digest, length = store.put(payload)
    assert length == len(payload)
    assert store.get(digest, expected_len=length) == payload


def test_no_temp_files_left_behind(tmp_path: Path):
    store = BlobStore(tmp_path)
    store.put(b"x" * 1000)
    assert list((tmp_path / "tmp").glob("*")) == []


def test_directories_created_with_mode_0o700(tmp_path: Path):
    """Directories must be created with mode 0o700 for proper access control."""
    store = BlobStore(tmp_path)
    digest, _ = store.put(b"test data")

    # Check that tmp directory is 0o700
    tmp_dir_mode = (tmp_path / "tmp").stat().st_mode & 0o777
    assert tmp_dir_mode == 0o700, f"tmp directory mode is {oct(tmp_dir_mode)}, expected 0o700"

    # Check that digest directories are 0o700
    blob_path = store.path_for(digest)
    for parent in [blob_path.parent, blob_path.parent.parent]:
        parent_mode = parent.stat().st_mode & 0o777
        assert parent_mode == 0o700, f"Directory {parent} mode is {oct(parent_mode)}, expected 0o700"


def test_blob_file_created_with_mode_0o600(tmp_path: Path):
    """Blob files must be created with mode 0o600."""
    store = BlobStore(tmp_path)
    digest, _ = store.put(b"sensitive client data")

    blob_path = store.path_for(digest)
    file_mode = blob_path.stat().st_mode & 0o777
    assert file_mode == 0o600, f"Blob file mode is {oct(file_mode)}, expected 0o600"


def test_put_repairs_a_same_length_corruption(tmp_path: Path):
    """The nastier torn write: same length, wrong bytes."""
    store = BlobStore(tmp_path)
    digest, _ = store.put(b"a" * 500)
    store.path_for(digest).write_bytes(b"b" * 500)  # same length, wrong content

    again, length = store.put(b"a" * 500)
    assert again == digest and length == 500
    assert store.get(digest) == b"a" * 500, "put() did not repair the blob"


def test_nested_directory_creation_secures_all_levels(tmp_path: Path):
    """All directories created by BlobStore should be 0o700, even if parents don't exist."""
    # Create BlobStore at a path where parents don't exist
    nested_root = tmp_path / "nonexistent" / "nested" / "root"
    store = BlobStore(nested_root)
    digest, _ = store.put(b"test data")

    # Check that directories created by BlobStore are 0o700
    tmp_dir = nested_root / "tmp"
    for path in [tmp_dir, nested_root, tmp_path / "nonexistent" / "nested"]:
        mode = path.stat().st_mode & 0o777
        assert mode == 0o700, f"Created directory {path} has mode {oct(mode)}, expected 0o700"


# --- M1: path_for() must validate the digest format, not treat an
# arbitrary string as a filesystem path ---


def test_path_for_rejects_absolute_path_escape(tmp_path: Path):
    """Without a format check, an absolute component resets the join --
    `path_for("/etc/passwd")` used to return `/etc/passwd` outright,
    escaping the engagement root entirely."""
    store = BlobStore(tmp_path)
    with pytest.raises(CorruptBlob):
        store.path_for("/etc/passwd")


def test_path_for_rejects_relative_path_escape(tmp_path: Path):
    store = BlobStore(tmp_path)
    with pytest.raises(CorruptBlob):
        store.path_for("../../etc/passwd")


def test_path_for_rejects_malformed_digest(tmp_path: Path):
    store = BlobStore(tmp_path)
    with pytest.raises(CorruptBlob):
        store.path_for("abc")


def test_path_for_accepts_a_real_digest(tmp_path: Path):
    store = BlobStore(tmp_path)
    digest, _ = store.put(b"hello")
    assert store.path_for(digest) == store.root / digest[:2] / digest[2:4] / digest


def test_get_rejects_malformed_digest_without_touching_disk(tmp_path: Path):
    """get() must fail the format check before it ever reads a file --
    otherwise a malformed digest is a file-existence/size oracle via the
    exception message."""
    store = BlobStore(tmp_path)
    with pytest.raises(CorruptBlob):
        store.get("/etc/passwd")


def test_preexisting_directories_left_alone(tmp_path: Path):
    """Regression test: BlobStore must not chmod pre-existing directories."""
    # Create a pre-existing directory with mode 0o755
    preexisting = tmp_path / "preexisting"
    preexisting.mkdir(mode=0o755)

    # Create BlobStore in a subdirectory beneath it
    store_root = preexisting / "store" / "root"
    store = BlobStore(store_root)
    store.put(b"test data")

    # Assert the pre-existing directory was NOT modified
    mode = preexisting.stat().st_mode & 0o777
    assert mode == 0o755, f"Pre-existing directory was modified to {oct(mode)}, expected 0o755"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_blobs.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.store.blobs'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/hx/store/blobs.py
"""Content-addressed blob storage, scoped to one engagement.

Blobs are partitioned per engagement rather than globally. Cross-engagement
dedupe would save little at 320 req/s of mostly-distinct bodies, and it would
make contractual data destruction impossible to perform correctly: deleting
client A's data must not corrupt client B's evidence.
"""
from __future__ import annotations

import hashlib
import os
import re
import uuid
from pathlib import Path

from hx.store.paths import secure_mkdir

_HEX64 = re.compile(r"[0-9a-f]{64}")


class CorruptBlob(Exception):
    """A blob's bytes do not match the digest or length they are stored under."""


class BlobStore:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.tmp = self.root / "tmp"
        secure_mkdir(self.tmp)

    def path_for(self, digest: str) -> Path:
        """Resolve a digest to its on-disk path.

        `digest` must be a bare 64-character lowercase hex sha256. Without
        this check, an absolute or `..`-laden string resets or escapes the
        join (`path_for("/etc/passwd")` returns `/etc/passwd` outright), and
        blob refs will arrive over the bridge from the JVM in Plan 2 -- an
        attacker-controlled string reaching this function is not hypothetical
        there.
        """
        if not _HEX64.fullmatch(digest):
            raise CorruptBlob(f"not a valid digest: {digest!r}")
        return self.root / digest[:2] / digest[2:4] / digest

    def put(self, data: bytes) -> tuple[str, int]:
        digest = hashlib.sha256(data).hexdigest()
        final = self.path_for(digest)
        if final.exists():
            try:
                if hashlib.sha256(final.read_bytes()).hexdigest() == digest:
                    return digest, len(data)
            except OSError:
                pass  # unreadable: repair it

        # Create directories with mode 0o700
        secure_mkdir(final.parent)

        # Create staging file with mode 0o600
        staging = self.tmp / f"{uuid.uuid4().hex}.part"
        fd = os.open(str(staging), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        except Exception:
            # The `with` block already closed fd via fdopen()'s __exit__ in
            # the common case (write/fsync failure inside the block); this
            # only catches fd surviving unclosed if fdopen() itself raised
            # before the file object existed to close it. Closing an
            # already-closed fd raises OSError (EBADF), which is the one
            # error worth swallowing here -- anything else should surface.
            try:
                os.close(fd)
            except OSError:
                pass
            staging.unlink(missing_ok=True)
            raise

        written = staging.read_bytes()
        if hashlib.sha256(written).hexdigest() != digest:
            staging.unlink(missing_ok=True)
            raise CorruptBlob(f"digest mismatch writing {digest}")

        os.replace(staging, final)
        os.chmod(final, 0o600)
        return digest, len(data)

    def get(self, digest: str, expected_len: int | None = None) -> bytes:
        path = self.path_for(digest)
        if not path.exists():
            raise CorruptBlob(f"blob {digest} missing")
        data = path.read_bytes()
        if expected_len is not None and len(data) != expected_len:
            raise CorruptBlob(
                f"blob {digest} length {len(data)} != expected {expected_len}"
            )
        if hashlib.sha256(data).hexdigest() != digest:
            raise CorruptBlob(f"blob {digest} failed digest verification")
        return data
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_blobs.py -v`
Expected: PASS, 7 passed

- [ ] **Step 5: Commit**

```bash
git add src/hx/store/blobs.py tests/test_blobs.py
git commit -m "feat(store): content-addressed blob store with atomic writes and verification"
```

---

### Task 3: Engagement config

**Files:**
- Create: `src/hx/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `hx.config.Config` dataclass with fields: `name: str`, `client: str`, `safety_profile: str`, `scope_include: list[str]`, `scope_exclude: list[str]`, `render_allow: list[str]`, `dangerous_paths: list[str]`, `checks: dict[str, bool]`, `rate_limit_rps: int`, `max_concurrency: int`, `identities: dict[str, dict]`, `preserve_segments: list[str]`, `slug_threshold: int`
  - `hx.config.load(path: Path) -> Config`
  - `hx.config.dumps(cfg: Config) -> str`
  - `hx.config.DEFAULT_DANGEROUS_PATHS: list[str]`
  - `hx.config.DEFAULT_CHECKS: dict[str, bool]`
  - `hx.config.VALID_PROFILES: tuple[str, ...]` — used by the CLI in Task 5
  - `hx.config.ConfigError(Exception)`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config.py
from pathlib import Path

import pytest
import yaml

from hx import config


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_loads_minimal_config(tmp_path: Path):
    p = _write(
        tmp_path,
        """
name: acme-2026-09
client: Acme Corp
scope:
  include: ["https://app.acme.com/*"]
""",
    )
    cfg = config.load(p)
    assert cfg.name == "acme-2026-09"
    assert cfg.client == "Acme Corp"
    assert cfg.scope_include == ["https://app.acme.com/*"]


def test_defaults_are_safe(tmp_path: Path):
    """Unspecified means safe: production profile, mutating checks off."""
    p = _write(
        tmp_path,
        """
name: acme
client: Acme
scope:
  include: ["https://app.acme.com/*"]
""",
    )
    cfg = config.load(p)
    assert cfg.safety_profile == "production"
    assert cfg.checks["active_mutate"] is False
    assert cfg.checks["active_dos"] is False
    assert cfg.checks["passive"] is True
    # `<= 10` and a substring of a joined string both pass even if the real
    # default drifted -- e.g. a join could make an unrelated pair of entries
    # spell "logout" across a boundary. Assert the actual documented default
    # value and check membership in the list itself.
    assert cfg.rate_limit_rps == 5
    assert "*/logout*" in cfg.dangerous_paths


def test_empty_scope_include_is_rejected(tmp_path: Path):
    p = _write(tmp_path, "name: acme\nclient: Acme\nscope:\n  include: []\n")
    with pytest.raises(config.ConfigError, match="scope.include"):
        config.load(p)


def test_missing_name_is_rejected(tmp_path: Path):
    p = _write(tmp_path, "client: Acme\nscope:\n  include: ['https://a/*']\n")
    with pytest.raises(config.ConfigError, match="name"):
        config.load(p)


def test_unknown_safety_profile_is_rejected(tmp_path: Path):
    p = _write(
        tmp_path,
        "name: a\nclient: b\nsafety_profile: yolo\nscope:\n  include: ['https://a/*']\n",
    )
    with pytest.raises(config.ConfigError, match="safety_profile"):
        config.load(p)


def test_dumps_round_trips(tmp_path: Path):
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\n",
    )
    cfg = config.load(p)
    p2 = tmp_path / "again.yaml"
    p2.write_text(config.dumps(cfg), encoding="utf-8")
    assert config.load(p2) == cfg


def test_checks_string_false_is_rejected(tmp_path: Path):
    """String 'false' must not coerce to bool True; must be rejected."""
    p = _write(
        tmp_path,
        'name: a\nclient: b\nscope:\n  include: ["https://a/*"]\nchecks:\n  active_mutate: "false"\n',
    )
    with pytest.raises(config.ConfigError, match="active_mutate.*boolean"):
        config.load(p)


def test_checks_true_bool_is_honoured(tmp_path: Path):
    """A real bool true in checks must be accepted."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\nchecks:\n  active_mutate: true\n",
    )
    cfg = config.load(p)
    assert cfg.checks["active_mutate"] is True


def test_checks_unknown_class_is_rejected(tmp_path: Path):
    """An unknown check class must be rejected, with a message naming valid classes."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\nchecks:\n  no_such_class: true\n",
    )
    with pytest.raises(config.ConfigError, match="no_such_class.*valid check class.*passive.*active_mutate"):
        config.load(p)


def test_dangerous_paths_string_is_rejected(tmp_path: Path):
    """A string dangerous_paths must not be iterated into chars; must be rejected."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\ndangerous_paths: custom\n",
    )
    with pytest.raises(config.ConfigError, match="dangerous_paths.*list"):
        config.load(p)


def test_scope_include_string_is_rejected(tmp_path: Path):
    """A string scope.include must not be iterated into chars; must be rejected."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: 'https://a/*'\n",
    )
    with pytest.raises(config.ConfigError, match="include.*list"):
        config.load(p)


def test_rate_limit_rps_zero_is_rejected(tmp_path: Path):
    """rate_limit_rps must be >= 1, not 0."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\nrate_limit_rps: 0\n",
    )
    with pytest.raises(config.ConfigError, match="rate_limit_rps.*integer >= 1"):
        config.load(p)


def test_rate_limit_rps_negative_is_rejected(tmp_path: Path):
    """rate_limit_rps must be >= 1, not negative."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\nrate_limit_rps: -5\n",
    )
    with pytest.raises(config.ConfigError, match="rate_limit_rps.*integer >= 1"):
        config.load(p)


def test_rate_limit_rps_bool_is_rejected(tmp_path: Path):
    """bool is an int subclass; rate_limit_rps: true must be rejected."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\nrate_limit_rps: true\n",
    )
    with pytest.raises(config.ConfigError, match="rate_limit_rps.*integer >= 1"):
        config.load(p)


def test_scope_string_raises_config_error(tmp_path: Path):
    """scope: 'oops' must raise ConfigError, not AttributeError."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope: oops\n",
    )
    with pytest.raises(config.ConfigError, match="scope.*mapping"):
        config.load(p)


def test_checks_string_raises_config_error(tmp_path: Path):
    """checks: 'yes' must raise ConfigError, not ValueError."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\nchecks: yes\n",
    )
    with pytest.raises(config.ConfigError, match="checks.*mapping"):
        config.load(p)


def test_explicit_empty_dangerous_paths_is_honoured(tmp_path: Path):
    """An explicit empty dangerous_paths: [] must NOT be replaced by defaults."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\ndangerous_paths: []\n",
    )
    cfg = config.load(p)
    assert cfg.dangerous_paths == []


def test_invalid_yaml_raises_config_error(tmp_path: Path):
    """Malformed YAML must raise ConfigError, not yaml.YAMLError."""
    p = _write(tmp_path, "{ invalid yaml: [")
    with pytest.raises(config.ConfigError, match="invalid YAML"):
        config.load(p)


# --- M6: name and client are the only unvalidated types in this module ---


def test_name_int_is_rejected(tmp_path: Path):
    """`if not raw.get(required)` is a truthiness test: `name: 123` is
    truthy and used to load fine, reaching the database and the report as
    a coerced value."""
    p = _write(
        tmp_path,
        "name: 123\nclient: Acme\nscope:\n  include: ['https://a/*']\n",
    )
    with pytest.raises(config.ConfigError, match="name"):
        config.load(p)


def test_client_bool_is_rejected(tmp_path: Path):
    """`client: true` is truthy and used to load fine for the same reason."""
    p = _write(
        tmp_path,
        "name: acme\nclient: true\nscope:\n  include: ['https://a/*']\n",
    )
    with pytest.raises(config.ConfigError, match="client"):
        config.load(p)


def test_name_blank_string_is_rejected(tmp_path: Path):
    """A whitespace-only name is a string (truthy), but not a real name."""
    p = _write(
        tmp_path,
        "name: '   '\nclient: Acme\nscope:\n  include: ['https://a/*']\n",
    )
    with pytest.raises(config.ConfigError, match="name"):
        config.load(p)


# --- Test-suite fix: a direct Config() construction, bypassing load()
# entirely ---


def test_direct_config_construction_has_safe_defaults():
    """`hx new` builds Config(...) directly and never calls load() -- so
    every default_factory field must be independently proven safe here,
    not only when reached through the YAML-parsing path."""
    cfg = config.Config(
        name="acme-2026-09",
        client="Acme Corp",
        scope_include=["https://app.acme.com/*"],
    )
    assert cfg.safety_profile == "production"
    assert cfg.checks["active_mutate"] is False
    assert cfg.checks["active_dos"] is False
    assert cfg.rate_limit_rps == 5
    assert "*/logout*" in cfg.dangerous_paths
    assert cfg.scope_exclude == []
    assert cfg.identities == {}


def test_direct_config_construction_round_trips_through_dumps_and_load(tmp_path: Path):
    """The same direct-construction path `hx new` uses, proven to still
    dump and reload correctly -- not just to have safe field values."""
    cfg = config.Config(
        name="acme-2026-09",
        client="Acme Corp",
        scope_include=["https://app.acme.com/*"],
    )
    p = tmp_path / "config.yaml"
    p.write_text(config.dumps(cfg), encoding="utf-8")
    assert config.load(p) == cfg


def test_a_blank_entry_in_a_string_list_is_refused(tmp_path: Path):
    """A stray blank line in scope.exclude takes the engagement to deny-all.

    The extension already fails closed on it -- an empty pattern makes
    Rule.forExclude throw and the whole decision becomes scope_denied -- so the
    run stops rather than proceeding unprotected. That is the right direction
    and it is pinned on the Java side. The cost is that the operator learns
    mid-run, from a refusal, that a config written hours ago has a blank line
    in it. Catching it at load time is the same answer, delivered when it is
    cheap to act on.
    """
    head = 'name: a\nclient: b\n'
    for body in (
        'scope:\n  include:\n    - ""\n',
        'scope:\n  include: ["https://a/*"]\n  exclude:\n    - ""\n',
        'scope:\n  include: ["https://a/*"]\ndangerous_paths:\n  - "   "\n',
        'scope:\n  include: ["https://a/*"]\nrender_allow:\n  - ""\n',
    ):
        p = _write(tmp_path, head + body)
        with pytest.raises(config.ConfigError, match=r"\[0\] is blank"):
            config.load(p)


# --- Task 6: the request budget -------------------------------------------


def test_max_requests_defaults_to_javas_documented_default():
    """`Distress.java`/`HxExtension.DEFAULT_MAX_REQUESTS` documents 2000 as
    `Limits.arm()`'s fallback. Matching it means adding the key changes no
    behaviour for an operator who sets nothing -- the number was always
    2000, it was just never said."""
    cfg = config.Config(
        name="acme-2026-09", client="Acme Corp",
        scope_include=["https://app.acme.com/*"])
    assert cfg.max_requests == 2000


def test_max_requests_must_be_a_positive_integer(tmp_path: Path):
    for bad in ("0", "-1", "true", "many"):
        p = _write(
            tmp_path,
            "name: a\nclient: b\nscope:\n  include: ['https://a/*']\n"
            f"max_requests: {bad}\n",
        )
        with pytest.raises(config.ConfigError, match="max_requests.*integer >= 1"):
            config.load(p)


def test_a_deliberately_empty_list_is_still_allowed(tmp_path: Path):
    """The blank-ENTRY guard must not become a no-empty-LISTS guard.

    An explicitly written empty list is the operator saying so in the file,
    which the spec requires to stay possible and reviewable. Only a blank entry
    inside a list is meaningless.
    """
    p = _write(tmp_path, 'name: a\nclient: b\nscope:\n  include: ["https://a/*"]\n  exclude: []\n')
    cfg = config.load(p)
    assert cfg.scope_exclude == []


# --- Task 1 (identity plan): the identity declaration ----------------------


def test_credential_headers_matches_the_probe_modules_own_list():
    """One fact, two casings, two modules. `hx.checks.probe.CREDENTIAL_HEADERS`
    is already hand-verified against `Redactor.CREDENTIAL_HEADERS`
    (extension/src/hx/send/Redactor.java:143-144, lower-cased there for
    ASCII-insensitive comparison). This pins `config.CREDENTIAL_HEADERS`
    against THAT copy rather than re-deriving the claim a third time, so the
    title-cased header names an operator writes in `inject.header` cannot
    silently drift from the send path's own enforcement list."""
    from hx.checks import probe
    assert {h.lower() for h in config.CREDENTIAL_HEADERS} == probe.CREDENTIAL_HEADERS


def _identity_yaml(**over) -> str:
    body = {
        "strategy": "static",
        "inject": {"header": "Cookie", "value_from_env": "HX_ID_USER"},
        "liveness": {"path": "/account", "expect_body": "Sign out"},
    }
    body.update(over)
    return yaml.safe_dump({
        "name": "e", "client": "c",
        "scope": {"include": ["https://app.test/*"]},
        "identities": {"user": body},
    })


def test_a_static_identity_parses_into_a_typed_declaration(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(_identity_yaml(), encoding="utf-8")
    cfg = config.load(p)
    ident = cfg.identities["user"]
    assert ident.id == "user" and ident.strategy == "static"
    assert ident.inject.header == "Cookie"
    assert ident.inject.value_from_env == "HX_ID_USER"
    assert ident.liveness.expect_body == "Sign out"
    assert ident.liveness.every_n_probes == 25      # the documented default
    assert ident.refresh is None


def test_the_declaration_carries_no_secret_and_dumps_none(tmp_path, monkeypatch):
    # THE POINT OF THE WHOLE SHAPE. scope_version.yaml stores this text
    # verbatim in an append-only table, so a credential here is permanent.
    monkeypatch.setenv("HX_ID_USER", "session=SUPERSECRET")
    p = tmp_path / "config.yaml"
    p.write_text(_identity_yaml(), encoding="utf-8")
    cfg = config.load(p)
    rendered = config.dumps(cfg)
    assert "SUPERSECRET" not in rendered
    assert "HX_ID_USER" in rendered, "the declaration must survive a round trip"
    assert config.load_text(rendered).identities["user"] == cfg.identities["user"]


def test_a_credential_header_outside_the_three_is_refused(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(_identity_yaml(
        inject={"header": "X-Api-Key", "value_from_env": "HX_ID_USER"}),
        encoding="utf-8")
    with pytest.raises(config.ConfigError, match="Cookie"):
        config.load(p)


def test_an_identity_without_liveness_is_refused(tmp_path):
    p = tmp_path / "config.yaml"
    body = yaml.safe_load(_identity_yaml())
    del body["identities"]["user"]["liveness"]
    p.write_text(yaml.safe_dump(body), encoding="utf-8")
    with pytest.raises(config.ConfigError, match="liveness"):
        config.load(p)


def test_liveness_without_expect_body_is_refused(tmp_path):
    # A canary satisfied by a status only is satisfied by a 200 LOGIN PAGE,
    # which is the whole reason retirement was removed from active checks.
    p = tmp_path / "config.yaml"
    p.write_text(_identity_yaml(liveness={"path": "/account"}), encoding="utf-8")
    with pytest.raises(config.ConfigError, match="expect_body"):
        config.load(p)


def test_a_static_identity_may_not_declare_refresh(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(_identity_yaml(
        refresh={"command": ["true"], "value_from": "stdout"}), encoding="utf-8")
    with pytest.raises(config.ConfigError, match="static"):
        config.load(p)


def test_a_programmatic_identity_must_declare_refresh(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(_identity_yaml(strategy="programmatic"), encoding="utf-8")
    with pytest.raises(config.ConfigError, match="refresh"):
        config.load(p)


def test_refresh_command_must_be_a_list_never_a_string(tmp_path):
    # A string would invite shell=True at the call site. The list is the
    # guarantee that no shell ever sees it.
    p = tmp_path / "config.yaml"
    p.write_text(_identity_yaml(
        strategy="programmatic",
        refresh={"command": "mint.sh --admin", "value_from": "stdout"}),
        encoding="utf-8")
    with pytest.raises(config.ConfigError, match="list"):
        config.load(p)


def test_scan_identity_must_name_a_declared_identity(tmp_path):
    p = tmp_path / "config.yaml"
    body = yaml.safe_load(_identity_yaml())
    body["scan_identity"] = "nobody"
    p.write_text(yaml.safe_dump(body), encoding="utf-8")
    with pytest.raises(config.ConfigError, match="nobody"):
        config.load(p)


def test_a_programmatic_identity_needs_no_value_from_env(tmp_path):
    """Deviation from the task-1 brief, recorded here rather than silently
    fixed: the brief's sketch made `inject.value_from_env` unconditionally
    required, but spec §4's own `admin` example is a programmatic identity
    whose `inject` block names only a header (`{header: Authorization}`) --
    its credential comes from `refresh.command`'s stdout, not the
    environment, so there is no env var to name. Requiring one unconditionally
    would refuse the spec's own example. `value_from_env` is required only
    for `static`, where the environment is the sole source of the value."""
    p = tmp_path / "config.yaml"
    p.write_text(_identity_yaml(
        strategy="programmatic",
        inject={"header": "Authorization"},
        refresh={"command": ["./mint.sh"], "value_from": "stdout"}),
        encoding="utf-8")
    cfg = config.load(p)
    ident = cfg.identities["user"]
    assert ident.inject.value_from_env is None
    assert ident.inject.header == "Authorization"
    rendered = config.dumps(cfg)
    assert "value_from_env" not in rendered
    assert config.load_text(rendered).identities["user"] == ident


def test_a_static_identity_without_value_from_env_is_refused(tmp_path):
    """The inverse of the programmatic case, and the half that was unpinned.

    A programmatic identity legitimately has no `value_from_env` -- its
    credential comes from `refresh.command`'s stdout, which is why spec section
    4's own `admin` example omits it. A STATIC one has no other source, so
    omitting it there leaves an identity that can never produce a credential:
    `hx.identity.resolve` would have no variable to read and the run would
    either halt or, worse, issue anonymously against an application that
    requires a session -- answering `clean` about a view none of its users are
    in. The rule was enforced from the start; only this direction of it went
    untested, which is how it would have regressed silently.
    """
    p = tmp_path / "config.yaml"
    p.write_text(_identity_yaml(inject={"header": "Cookie"}), encoding="utf-8")
    with pytest.raises(config.ConfigError, match="value_from_env"):
        config.load(p)


# --- branch fix A: `identities.<id>.origins`, the operator's widening ------
#
# F1 of the whole-branch review, first half. The credential used to be
# registered for every host in `scope.include` while the canary proved one,
# so a client's live session went to whatever third party the operator had
# authorised for SCANNING. The default is now the proven host alone
# (`hx.scan._identity_bracket`), and this key is how an operator says a
# session genuinely spans more than one -- a decision recorded in
# `config.yaml`, which is the shape spec section 4 asks for from anything
# that increases blast radius.


def test_an_identity_declares_no_origins_by_default(tmp_path):
    """ABSENT IS THE COMMON CASE AND MEANS "DO NOT WIDEN". The bound itself
    is not empty: `hx.scan._identity_bracket` turns `()` into the single
    origin the run's liveness canary is about to prove, which is a fact about
    the run's surfaces and cannot be known here."""
    p = tmp_path / "config.yaml"
    p.write_text(_identity_yaml(), encoding="utf-8")
    assert config.load(p).identities["user"].origins == ()


def test_declared_origins_parse_and_survive_a_round_trip(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(_identity_yaml(
        origins=["https://app.test/", "api.test"]), encoding="utf-8")
    cfg = config.load(p)
    assert cfg.identities["user"].origins == ("https://app.test/", "api.test")
    rendered = config.dumps(cfg)
    assert config.load_text(rendered).identities["user"] == cfg.identities["user"]


def test_an_identity_that_widened_nothing_renders_no_origins_key(tmp_path):
    """`scope_version.yaml` stores this text verbatim in an append-only
    table, and what belongs there is the operator's DECISION. The default is
    not one -- it is derived per run from the surface the canary goes to --
    so an engagement that never widened the bound renders the YAML it always
    did, and every pre-fix scope version stays byte-comparable."""
    p = tmp_path / "config.yaml"
    p.write_text(_identity_yaml(), encoding="utf-8")
    assert "origins" not in config.dumps(config.load(p))


def test_a_declared_but_empty_origins_list_is_refused(tmp_path):
    """The two are opposite intentions and must not collapse: absent is "I
    did not widen this", `[]` is "I chose nothing", and nothing is a bound
    that refuses every probe of the run as `identity_origin`. An operator who
    wants that wants `scan_identity` omitted."""
    p = tmp_path / "config.yaml"
    p.write_text(_identity_yaml(origins=[]), encoding="utf-8")
    with pytest.raises(config.ConfigError, match="non-empty list"):
        config.load(p)


@pytest.mark.parametrize("entry", ["", "   ", 7, None])
def test_an_origins_entry_that_is_not_a_non_empty_string_is_refused(
        tmp_path, entry):
    p = tmp_path / "config.yaml"
    p.write_text(_identity_yaml(origins=[entry]), encoding="utf-8")
    with pytest.raises(config.ConfigError, match="non-empty string"):
        config.load(p)


@pytest.mark.parametrize("entry", [
    "*.test",                    # a scope glob: `hostOf` reads `*.test`
    "https://*.acme.test/*",     # the same, URL-shaped
    "/account",                  # a path, so `hostOf` reads nothing at all
    "https://",                  # a scheme and nothing after it
    "[::1]:8080",                # cut at the first colon, leaving `[`
])
def test_an_origin_the_send_path_could_never_match_is_refused(tmp_path, entry):
    """THE REASON THIS CHECK EXISTS AT ALL. `Sender.appliesTo` compares the
    host it is about to connect to against `hostOf(origin)` -- exactly,
    case-insensitively, with no suffix or glob matching -- so an entry naming
    no matchable host bounds the credential to nothing and refuses every
    probe. Fail-closed, but silently: the operator wrote a widening and got a
    scan that could not send. Refusing at load says so in a sentence.

    The last case is why the charset check is not merely "non-empty": an IPv6
    literal is cut at its first colon and leaves `[`, which is a non-empty
    string that can never equal a host."""
    p = tmp_path / "config.yaml"
    p.write_text(_identity_yaml(origins=[entry]), encoding="utf-8")
    with pytest.raises(config.ConfigError, match="names no host"):
        config.load(p)


def test_the_loaders_host_reading_is_the_extensions_own(tmp_path):
    """A MIRROR, AND THE ORIGINAL IS THE ONE THAT GUARDS THE WIRE.
    `extension/src/hx/send/Sender.java`'s `hostOf` is what section 4 rests
    on; `config._origin_host` exists only to refuse an unmatchable entry
    early. The two must read the same string out of the same origin or this
    loader would accept a bound the send path reads differently -- so the
    cases below are transcribed from that method's own javadoc: everything
    after `://` and before the first `/`, `:` or `?`, lower-cased."""
    assert config._origin_host("https://App.Test:8443/x?y") == "app.test"
    assert config._origin_host("app.test") == "app.test"
    assert config._origin_host("  HTTP://api.test/  ") == "api.test"
    assert config._origin_host("/account") == ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.config'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/hx/config.py
"""Engagement configuration.

Defaults are chosen so that an under-specified config is a SAFE config: the
production profile, mutating and DoS checks off, a low rate limit. Anything
that increases blast radius must be written down explicitly, in the file,
where it is recorded and reviewable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

VALID_PROFILES = ("production", "staging")

DEFAULT_DANGEROUS_PATHS: list[str] = [
    "*/logout*",
    "*/signout*",
    "*/password*",
    "*/change-password*",
    "*/reset*",
    "*/delete*",
    "*/purge*",
    "*/deactivate*",
    "*/close-account*",
]

DEFAULT_CHECKS: dict[str, bool] = {
    "passive": True,
    "active_safe": True,
    "active_timing": True,
    "active_mutate": False,
    "active_dos": False,
}


class ConfigError(Exception):
    """The engagement config is missing something required, or is nonsense."""


# The three headers `Redactor.unmanagedCredential`
# (extension/src/hx/send/Redactor.java:143-144) already refuses when the
# extension did not itself inject them -- confirmed against that file rather
# than assumed: `CREDENTIAL_HEADERS = {"authorization", "cookie",
# "proxy-authorization"}`, byte for byte the same three, there lower-cased for
# ASCII-insensitive comparison. Injecting anything else through `identity`
# would not be a credential in the sense the send path enforces, and would
# not need any of this machinery. Not configurable: an operator cannot widen
# the set here without also widening what the extension itself will carry.
CREDENTIAL_HEADERS = ("Cookie", "Authorization", "Proxy-Authorization")

VALID_STRATEGIES = ("static", "programmatic")


@dataclass(frozen=True)
class Inject:
    """Which header carries the credential, and where the value comes from.

    `value_from_env` names an environment variable rather than holding a
    value -- see the module-level note on `Config.identities` for why. It is
    required for a `static` identity (the only place a value ever comes from
    the environment) and optional for a `programmatic` one, whose credential
    instead comes from `Refresh.command`'s stdout at resolve time (spec §4's
    `admin` example declares `inject: {header: Authorization}` with no
    `value_from_env` at all).
    """
    header: str
    value_from_env: str | None = None


@dataclass(frozen=True)
class Liveness:
    """How this identity proves it is still logged in.

    `expect_body` is REQUIRED and is the load-bearing field. A canary that
    accepted a status code would be satisfied by an application answering a
    logged-out request with a 200 login page -- the one shape no
    response-status rule can catch, and the one `hx.scan._retirable` refused
    ALL active-check retirement over until this plan gave it a proof to read.
    It reads one now: an active check's `considered` is honoured for a run
    whose canary came back `proven`, so a canary a login page could satisfy
    would hand that hazard straight back with a stamp on it. This field is
    what stops it.
    """
    path: str
    expect_body: str
    expect_absent: str | None = None
    every_n_probes: int = 25


@dataclass(frozen=True)
class Refresh:
    # A LIST, never a string. `hx.identity.refresh` (a later task) executes
    # this without a shell, and the list is what makes "no shell ever sees
    # it" true regardless of what an operator writes -- a string would invite
    # `shell=True` at the call site however it was spelled.
    command: tuple[str, ...]
    value_from: str = "stdout"


@dataclass(frozen=True)
class Identity:
    id: str
    strategy: str
    inject: Inject
    liveness: Liveness
    refresh: Refresh | None = None
    # WHERE THIS IDENTITY'S CREDENTIAL MAY BE APPLIED, and EMPTY IS NOT
    # "everywhere" -- it is "the operator did not widen it", and
    # `hx.scan._identity_bracket` then bounds the credential to the ONE
    # origin the liveness canary is about to prove. Spec section 5 as
    # amended 2026-08-30: it used to default to `scope.include`, which made
    # the bound useless on exactly the engagements it exists for -- a scope
    # naming the app, an API, an SSO provider and a CDN had the client's
    # live session sent to all four while the canary proved one.
    #
    # AN OPERATOR MAY WIDEN IT, AND WRITING IT HERE IS THE POINT. A session
    # that legitimately spans two hosts is a fact only the operator knows;
    # section 4's whole shape is that anything increasing blast radius is a
    # decision recorded in `config.yaml` rather than a default. Widening
    # origins does NOT widen the proof: `hx.scan._retirable` still retires
    # only on the origin the canary reached.
    #
    # ENTRIES ARE HOSTS OR URL PREFIXES, and `_origin_host` below refuses
    # anything the extension's `Sender.hostOf` would read as no host at all
    # -- a glob, a bare path -- because such an entry matches nothing and
    # would be a bound an operator believed in and never got.
    origins: tuple[str, ...] = ()


# The host characters `Sender.appliesTo` can match. A host name is compared
# byte for byte and case-insensitively against `req.host()`, so anything
# outside this set -- a `*`, a space, a `[` left by an IPv6 literal `hostOf`
# cut at its first colon -- can never equal any host a send frame carries.
_ORIGIN_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-_")


def _origin_host(origin: str) -> str:
    """The host an `origins` entry names, the way the extension reads it.

    A DELIBERATE MIRROR OF `Sender.hostOf`, and the extension's copy is the
    one spec section 4 rests on: everything after `://` and before the first
    `/`, `:` or `?`, lower-cased. This one exists so an entry that would
    match no host is refused at LOAD time with a sentence naming it, rather
    than at run time as a silent `identity_origin` refusal of every probe --
    the same division of labour as `codec._refuse_unwritable` (an early,
    better-worded refusal) and `IdentityRegistry.checkWritable` (the one that
    actually guards the wire).

    Returning "" for an entry with no readable host is the fail-closed
    answer, and `_identity` turns it into a `ConfigError` rather than
    accepting a bound that binds nothing.
    """
    rest = origin.strip().lower()
    scheme = rest.find("://")
    if scheme >= 0:
        rest = rest[scheme + 3:]
    cut = len(rest)
    for delimiter in ("/", ":", "?"):
        at = rest.find(delimiter)
        if 0 <= at < cut:
            cut = at
    return rest[:cut]


def _identity(name: str, raw: dict) -> Identity:
    """Parse one `identities.<name>` block into a declaration.

    Structurally cannot carry a resolved secret: every field here is a name
    (a header, an env var, a command) or a proof (a liveness signature),
    never a value. Task 2's `hx.identity.resolve` reads the environment
    separately and keeps the result off this type entirely.
    """
    if not isinstance(raw, dict):
        raise ConfigError(f"identities.{name} must be a mapping")

    strategy = raw.get("strategy")
    if strategy not in VALID_STRATEGIES:
        raise ConfigError(
            f"identities.{name}.strategy must be one of {VALID_STRATEGIES}, "
            f"got {strategy!r}"
        )

    inj = _mapping(raw, "inject")
    header = inj.get("header")
    if header not in CREDENTIAL_HEADERS:
        raise ConfigError(
            f"identities.{name}.inject.header must be one of "
            f"{CREDENTIAL_HEADERS}, got {header!r}"
        )
    env = inj.get("value_from_env")
    if env is not None and (not isinstance(env, str) or not env.strip()):
        raise ConfigError(
            f"identities.{name}.inject.value_from_env must be a non-empty "
            "string naming an environment variable when given; a credential "
            "may not be written here"
        )
    if strategy == "static" and not env:
        raise ConfigError(
            f"identities.{name}.inject.value_from_env is required for a "
            "static identity: it is the only source of the credential a "
            "static identity has, and the config must name where the "
            "secret comes from without ever holding it"
        )

    live = _mapping(raw, "liveness")
    if not live:
        raise ConfigError(
            f"identities.{name} has no liveness block. An identity that "
            "cannot prove it is live can never be `proven`, and traffic "
            "issued under it is indistinguishable from anonymous traffic"
        )
    expect = live.get("expect_body")
    if not isinstance(expect, str) or not expect.strip():
        raise ConfigError(
            f"identities.{name}.liveness.expect_body is required and must "
            "be a non-empty string: a signature only an AUTHENTICATED "
            "response carries. A status code is not one -- a 200 login "
            "page has one too, and accepting that is the exact defect this "
            "declaration exists to close"
        )
    path = live.get("path")
    if not isinstance(path, str) or not path.startswith("/"):
        raise ConfigError(
            f"identities.{name}.liveness.path must be an origin-form path "
            f"starting with '/', got {path!r}"
        )
    absent = live.get("expect_absent")
    if absent is not None and (not isinstance(absent, str) or not absent.strip()):
        raise ConfigError(
            f"identities.{name}.liveness.expect_absent, when given, must be "
            "a non-empty string"
        )
    liveness = Liveness(
        path=path,
        expect_body=expect,
        expect_absent=absent,
        every_n_probes=_positive_int(live, "every_n_probes", 25),
    )

    refresh_raw = _mapping(raw, "refresh")
    if strategy == "static" and refresh_raw:
        raise ConfigError(
            f"identities.{name} is static and may not declare refresh: "
            "there is no command to re-run, and a static credential that "
            "expired is a dead session, not a refreshable one"
        )
    if strategy == "programmatic" and not refresh_raw:
        raise ConfigError(
            f"identities.{name} is programmatic and must declare refresh"
        )

    refresh = None
    if refresh_raw:
        command = refresh_raw.get("command")
        if not isinstance(command, list) or not command:
            raise ConfigError(
                f"identities.{name}.refresh.command must be a non-empty "
                "list of arguments, never a string: it is executed without "
                "a shell, and a string would invite one"
            )
        if not all(isinstance(x, str) for x in command):
            raise ConfigError(
                f"every entry in identities.{name}.refresh.command must be "
                "a string"
            )
        value_from = refresh_raw.get("value_from", "stdout")
        if value_from != "stdout":
            raise ConfigError(
                f"identities.{name}.refresh.value_from must be 'stdout', "
                f"got {value_from!r}"
            )
        refresh = Refresh(command=tuple(command), value_from=value_from)

    return Identity(
        id=name,
        strategy=strategy,
        inject=Inject(header=header, value_from_env=env),
        liveness=liveness,
        refresh=refresh,
        origins=_origins(name, raw),
    )


def _origins(name: str, raw: dict) -> tuple[str, ...]:
    """`identities.<name>.origins`, validated, or `()` for the default.

    ABSENT IS THE SAFE ANSWER AND IS NOT SPELLED HERE: `hx.scan.
    _identity_bracket` turns `()` into the single origin the run's liveness
    canary is about to prove. This function's whole job is the OTHER case --
    an operator deliberately widening the bound -- and every refusal below is
    a widening that would not have widened anything.

    A DECLARED-BUT-EMPTY LIST IS REFUSED rather than read as the default. The
    two are opposite intentions -- "I did not think about this" and "I
    thought about it and chose nothing" -- and the second one bounds the
    credential to no host at all, so every probe of the run would be refused
    `identity_origin`. An operator who wants that wants `scan_identity`
    omitted.

    THE ENTRIES ARE NOT CHECKED AGAINST `scope.include`, deliberately. Scope
    patterns are globs and origins are hosts, so "is this host inside that
    glob" is a matcher this file does not have; and it would be a check with
    no teeth either way, because scope is enforced on the send path
    regardless -- an origin naming a host outside scope simply never gets a
    request to apply to. Origins narrow, they never widen what scope allows.
    """
    if "origins" not in raw:
        return ()
    declared = raw["origins"]
    if not isinstance(declared, list) or not declared:
        raise ConfigError(
            f"identities.{name}.origins must be a non-empty list of hosts or "
            "URL prefixes when given; omit the key entirely to bound the "
            "credential to the one host the liveness canary proves, which is "
            "the default and the safe answer"
        )
    for entry in declared:
        if not isinstance(entry, str) or not entry.strip():
            raise ConfigError(
                f"every entry in identities.{name}.origins must be a "
                f"non-empty string, got {entry!r}"
            )
        host = _origin_host(entry)
        if not host or set(host) - _ORIGIN_HOST_CHARS:
            raise ConfigError(
                f"identities.{name}.origins entry {entry!r} names no host the "
                "send path can match. An origin is a host (`api.acme.test`) "
                "or a URL prefix (`https://api.acme.test/`); the extension "
                "reads everything after '://' and before the first '/', ':' "
                "or '?' and compares it to the host it is about to connect "
                f"to, and {host!r} can never equal one. A glob is not an "
                "origin -- it would bound the credential to nothing and "
                "refuse every probe"
            )
    return tuple(entry.strip() for entry in declared)


@dataclass(frozen=True)
class Config:
    name: str
    client: str
    safety_profile: str = "production"
    scope_include: list[str] = field(default_factory=list)
    scope_exclude: list[str] = field(default_factory=list)
    render_allow: list[str] = field(default_factory=list)
    dangerous_paths: list[str] = field(default_factory=lambda: list(DEFAULT_DANGEROUS_PATHS))
    checks: dict[str, bool] = field(default_factory=lambda: dict(DEFAULT_CHECKS))
    rate_limit_rps: int = 5
    # `Limits.arm()` (extension/src/hx/send/Limits.java) falls back to this
    # same number -- documented in HxExtension.DEFAULT_MAX_REQUESTS -- when a
    # configure body omits `limit.max_requests`. Matching it means adding the
    # field to this dataclass changes no behaviour for an operator who set
    # nothing: the budget was always 2000, it was just never written down.
    max_requests: int = 2000
    max_concurrency: int = 2
    # A credential value must NEVER be reachable from here.
    # `hx.engagement.record_scope_version` writes the loaded config's YAML
    # verbatim into `scope_version.yaml` -- `_record_scope`'s `INSERT INTO
    # scope_version` at `engagement.py:114`, whose `yaml` column takes
    # `config.dumps(cfg)` whole -- a
    # table the schema calls "append-only: tamper-evidence for contract
    # disputes" -- so a secret on this object is a secret copied,
    # unredactably, into a table designed to be impossible to rewrite. Each
    # `Identity` names an environment variable instead; the value that
    # variable holds is resolved separately (`hx.identity.resolve`, a later
    # task) into an object that never touches `Config`. `dumps()` below is
    # built to make that structural, not just documented: it reads only
    # declaration fields off `Identity`, so there is no field to leak even by
    # accident.
    identities: dict[str, Identity] = field(default_factory=dict)
    # Which declared identity `hx scan` issues its probes under. `None` is
    # anonymous, same as before this field existed. Validated against
    # `identities` at load time -- see `load_text` -- so a typo here is a
    # config-time error, not a scan that silently runs unauthenticated.
    scan_identity: str | None = None
    # `preserve_segments` names path segments the normaliser must NOT template.
    # THE DEFAULT PROTECTS NOTHING, and an operator who leaves it alone should
    # know that: no rule in `hx.surface` matches `api`, `v1`, `v2` or `v3` at
    # any threshold above 2, so the list changes no template until you put
    # something in it that a rule would otherwise reach. That is a numeric
    # segment which is really a route -- a year, an API generation, a tenant
    # number -- which is what the field is for. `["2024", "2025"]` is a list
    # that does something; the shipped one is a placeholder.
    preserve_segments: list[str] = field(default_factory=lambda: ["api", "v1", "v2", "v3"])
    slug_threshold: int = 12


def _mapping(raw: dict, key: str) -> dict:
    """A YAML block that must be a mapping, or absent."""
    v = raw.get(key)
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise ConfigError(f"{key} must be a mapping, got {type(v).__name__}")
    return v


def _string_list(raw: dict, key: str, default: list[str]) -> list[str]:
    """A list of strings.

    Absent means "use the default". An explicitly written empty list means
    empty -- the operator said so in the file, which is what the spec's
    "written down explicitly, where it is recorded and reviewable" requires.

    A non-list is REJECTED rather than coerced.
    """
    if key not in raw or raw[key] is None:
        return list(default)
    v = raw[key]
    if not isinstance(v, list):
        raise ConfigError(f"{key} must be a list, got {type(v).__name__}")
    if not all(isinstance(x, str) for x in v):
        raise ConfigError(f"every entry in {key} must be a string")
    check_entries(key, v)
    return list(v)


def check_entries(key: str, values: list[str]) -> None:
    """Refuse a blank entry in a list of patterns.

    A blank entry means nothing to any consumer, and in a scope list it is
    actively dangerous: the extension refuses an empty pattern outright --
    Rule.forExclude("") throws and the whole decision becomes scope_denied --
    so one stray blank line in scope.exclude takes the engagement to deny-all
    mid-run. Failing closed there is right; failing HERE is better, because the
    operator finds out before the run rather than after the first refusal.

    A PUBLIC function rather than a branch inside _string_list, because
    _string_list only ever runs in load(), and load() is not the only way a
    Config is built. `hx new` constructs one directly from its options and
    dumps() it, so `hx new --exclude ''` wrote `exclude: ['', ...]` to
    config.yaml AND to the scope_version row while every check in this module
    passed -- the guard fired on the next `load()`, which is to say after the
    engagement existed. Not a bypass (the extension still fails closed), but
    the whole point of the guard was that the operator learns at `hx new`, and
    on that path they did not. cli.new() calls this before it builds anything.

    Narrow on purpose, and unchanged from where the check used to live: a blank
    ENTRY is refused, an explicitly empty LIST is not. The spec requires
    `exclude: []` to stay writable and reviewable.
    """
    for i, x in enumerate(values):
        if not x.strip():
            raise ConfigError(
                f"{key}[{i}] is blank; remove the entry or give it a value"
            )


def _positive_int(raw: dict, key: str, default: int) -> int:
    v = raw.get(key, default)
    # bool is a subclass of int; `rate_limit_rps: true` must not become 1.
    if isinstance(v, bool) or not isinstance(v, int) or v < 1:
        raise ConfigError(f"{key} must be an integer >= 1, got {v!r}")
    return v


def load(path: Path) -> Config:
    """Read `path` and parse it. Everything else lives in `load_text`.

    Two parsers that must agree is how they come to disagree, so `load`
    is reduced to the read and delegates parsing entirely -- `load_text` is
    the one place YAML becomes a `Config`, whether the text came from disk
    or, as the round-trip test does, from `dumps()` still in memory.
    """
    return load_text(Path(path).read_text(encoding="utf-8"))


def load_text(text: str) -> Config:
    # A YAML syntax error is "nonsense" by this module's own definition of
    # ConfigError. Wrapping it here means no caller has to know PyYAML is
    # the parser underneath.
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")

    # `if not raw.get(required)` is a truthiness test: `name: 123` and
    # `name: true` pass it (both truthy) and reach the database and the
    # report as coerced values. Every other field in this module rejects
    # rather than coerces; name/client must not be the exception.
    for required in ("name", "client"):
        value = raw.get(required)
        if not isinstance(value, str) or not value.strip():
            raise ConfigError(
                f"config key {required!r} must be a non-empty string, "
                f"got {value!r} ({type(value).__name__})"
            )

    profile = raw.get("safety_profile", "production")
    if profile not in VALID_PROFILES:
        raise ConfigError(
            f"safety_profile must be one of {VALID_PROFILES}, got {profile!r}"
        )

    scope = _mapping(raw, "scope")
    include = _string_list(scope, "include", [])
    if not include:
        raise ConfigError("scope.include must list at least one target pattern")

    # Build checks by iterating over what was written, rejecting unknown keys
    # and non-bool values. Do not use dict.update().
    checks = dict(DEFAULT_CHECKS)
    checks_raw = _mapping(raw, "checks")
    for key, value in checks_raw.items():
        if key not in DEFAULT_CHECKS:
            raise ConfigError(
                f"checks.{key} is not a valid check class. Valid classes are: {', '.join(DEFAULT_CHECKS.keys())}"
            )
        if not isinstance(value, bool):
            raise ConfigError(f"checks.{key} must be a boolean, got {type(value).__name__}")
        checks[key] = value

    identities = {
        ident_name: _identity(ident_name, body)
        for ident_name, body in _mapping(raw, "identities").items()
    }

    scan_identity = raw.get("scan_identity")
    if scan_identity is not None:
        if not isinstance(scan_identity, str):
            raise ConfigError(
                "scan_identity must be a string, got "
                f"{type(scan_identity).__name__}"
            )
        if scan_identity not in identities:
            raise ConfigError(
                f"scan_identity names {scan_identity!r}, which is not a "
                f"declared identity. Declared: {sorted(identities) or 'none'}"
            )

    return Config(
        name=raw["name"],
        client=raw["client"],
        safety_profile=profile,
        scope_include=include,
        scope_exclude=_string_list(scope, "exclude", []),
        render_allow=_string_list(raw, "render_allow", []),
        dangerous_paths=_string_list(raw, "dangerous_paths", DEFAULT_DANGEROUS_PATHS),
        checks=checks,
        rate_limit_rps=_positive_int(raw, "rate_limit_rps", 5),
        max_requests=_positive_int(raw, "max_requests", 2000),
        max_concurrency=_positive_int(raw, "max_concurrency", 2),
        identities=identities,
        scan_identity=scan_identity,
        preserve_segments=_string_list(raw, "preserve_segments", ["api", "v1", "v2", "v3"]),
        slug_threshold=_positive_int(raw, "slug_threshold", 12),
    )


def _identity_yaml(i: Identity) -> dict:
    """The DECLARATION, and structurally nothing else.

    Built field by field from the dataclass rather than by dumping an
    object, so there is no path by which a resolved credential could ride
    along: `Identity` has no field holding one (see `hx.identity.resolve`,
    a later task, which keeps secrets in a separate mapping that is never
    passed here). `scope_version.yaml` stores whatever this returns
    VERBATIM in an append-only table -- see the spec's §3.
    """
    out: dict = {
        "strategy": i.strategy,
        "inject": {"header": i.inject.header},
        "liveness": {
            "path": i.liveness.path,
            "expect_body": i.liveness.expect_body,
            "every_n_probes": i.liveness.every_n_probes,
        },
    }
    if i.inject.value_from_env is not None:
        out["inject"]["value_from_env"] = i.inject.value_from_env
    if i.liveness.expect_absent is not None:
        out["liveness"]["expect_absent"] = i.liveness.expect_absent
    if i.refresh is not None:
        out["refresh"] = {
            "command": list(i.refresh.command),
            "value_from": i.refresh.value_from,
        }
    if i.origins:
        # Omitted when empty, so an engagement that never widened the bound
        # renders the same YAML it always did -- and so `scope_version.yaml`
        # records the operator's DECISION to widen and nothing else. The
        # default is not a decision and has no business being written down as
        # one: it is derived per run from the surface the canary goes to,
        # which is a fact about the run rather than about the config.
        out["origins"] = list(i.origins)
    return out


def dumps(cfg: Config) -> str:
    return yaml.safe_dump(
        {
            "name": cfg.name,
            "client": cfg.client,
            "safety_profile": cfg.safety_profile,
            "scope": {"include": cfg.scope_include, "exclude": cfg.scope_exclude},
            "render_allow": cfg.render_allow,
            "dangerous_paths": cfg.dangerous_paths,
            "checks": cfg.checks,
            "rate_limit_rps": cfg.rate_limit_rps,
            "max_requests": cfg.max_requests,
            "max_concurrency": cfg.max_concurrency,
            "identities": {n: _identity_yaml(i) for n, i in cfg.identities.items()},
            "scan_identity": cfg.scan_identity,
            "preserve_segments": cfg.preserve_segments,
            "slug_threshold": cfg.slug_threshold,
        },
        sort_keys=False,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_config.py -v`
Expected: PASS, 6 passed

- [ ] **Step 5: Commit**

```bash
git add src/hx/config.py tests/test_config.py
git commit -m "feat(config): engagement config with safe-by-default values"
```

---

### Task 4: Engagement lifecycle and directory isolation

**Files:**
- Create: `src/hx/engagement.py`
- Test: `tests/test_engagement.py`

**Interfaces:**
- Consumes:
  - `hx.store.db.connect`, `hx.store.db.init_schema`
  - `hx.store.blobs.BlobStore`
  - `hx.config.Config`, `hx.config.load`, `hx.config.dumps`
- Produces:
  - `hx.engagement.Engagement` with attributes `id: str`, `root: Path`, `config: Config`, `db: sqlite3.Connection`, `blobs: BlobStore`
  - `hx.engagement.create(root: Path, cfg: Config, *, author: str) -> Engagement`
  - `hx.engagement.open_(root: Path) -> Engagement`
  - `hx.engagement.record_scope_version(eng: Engagement, *, author: str, reason: str) -> str` — returns the new `scope_version.id`
  - `hx.engagement.now_us() -> int`
  - `hx.engagement.EngagementError(Exception)`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_engagement.py
import hashlib
import os
import stat
from pathlib import Path

import pytest

from hx import config, engagement


def _cfg(name="acme-2026-09") -> config.Config:
    return config.Config(
        name=name, client="Acme Corp", scope_include=["https://app.acme.com/*"]
    )


def test_create_builds_isolated_directory(tmp_path: Path):
    eng = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    assert (eng.root / "hx.db").exists()
    assert (eng.root / "blobs").is_dir()
    assert (eng.root / "config.yaml").exists()
    assert (eng.root / "exports").is_dir()


def test_engagement_directory_is_not_world_readable(tmp_path: Path):
    eng = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    mode = stat.S_IMODE(eng.root.stat().st_mode)
    assert mode == 0o700, f"engagement dir mode {oct(mode)} leaks client data"


def test_create_writes_engagement_row_and_initial_scope_version(tmp_path: Path):
    eng = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    row = eng.db.execute("SELECT name, client, status FROM engagement").fetchone()
    assert row["name"] == "acme-2026-09"
    assert row["status"] == "active"
    sv = eng.db.execute("SELECT yaml, sha256, author FROM scope_version").fetchone()
    assert sv["author"] == "jimx"
    assert sv["sha256"] == hashlib.sha256(sv["yaml"].encode()).hexdigest()


def test_create_refuses_existing_directory(tmp_path: Path):
    engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    with pytest.raises(engagement.EngagementError, match="exists"):
        engagement.create(tmp_path / "acme", _cfg(), author="jimx")


def test_open_round_trips(tmp_path: Path):
    created = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    created.db.close()
    reopened = engagement.open_(tmp_path / "acme")
    assert reopened.id == created.id
    assert reopened.config.client == "Acme Corp"


def test_scope_versions_are_append_only(tmp_path: Path):
    """The query that matters under dispute is what was in scope at time T."""
    eng = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    first = eng.db.execute("SELECT id, sha256 FROM scope_version").fetchone()
    eng.config.scope_include.append("https://api.acme.com/*")
    second_id = engagement.record_scope_version(
        eng, author="jimx", reason="client added API host"
    )
    rows = eng.db.execute(
        "SELECT id, sha256 FROM scope_version ORDER BY effective_from_us"
    ).fetchall()
    assert len(rows) == 2
    assert rows[0]["id"] == first["id"]
    assert rows[0]["sha256"] == first["sha256"], "history was mutated"
    assert rows[1]["id"] == second_id


def test_two_engagements_share_nothing(tmp_path: Path):
    a = engagement.create(tmp_path / "acme", _cfg("acme"), author="jimx")
    b = engagement.create(tmp_path / "globex", _cfg("globex"), author="jimx")
    digest, _ = a.blobs.put(b"acme secret response")
    assert a.blobs.get(digest) == b"acme secret response"
    assert not b.blobs.path_for(digest).exists(), "blob leaked across engagements"
    assert a.root != b.root and a.id != b.id


# --- Controller fix (a): ancestor directories must not be created world-readable ---


def test_preexisting_ancestor_directory_is_left_alone(tmp_path: Path):
    """Regression test: create() must not chmod a pre-existing ancestor.

    root.mkdir(parents=True, mode=0o700) only applies the mode to the leaf
    directory it creates; any missing ancestor is created at the umask
    default, which can be world-readable and would leak the list of clients
    under engagement.
    """
    engagements_dir = tmp_path / "engagements"
    engagements_dir.mkdir(mode=0o755)

    eng = engagement.create(engagements_dir / "acme", _cfg(), author="jimx")

    mode = stat.S_IMODE(engagements_dir.stat().st_mode)
    assert mode == 0o755, f"pre-existing ancestor mode {oct(mode)} was changed"
    leaf_mode = stat.S_IMODE(eng.root.stat().st_mode)
    assert leaf_mode == 0o700


def test_missing_ancestor_directories_are_created_0o700(tmp_path: Path):
    """Any ancestor directory create() has to make on the way down must be
    0o700, not just the leaf engagement directory."""
    root = tmp_path / "clients" / "confidential" / "acme"
    engagement.create(root, _cfg(), author="jimx")

    for ancestor in (tmp_path / "clients", tmp_path / "clients" / "confidential", root):
        mode = stat.S_IMODE(ancestor.stat().st_mode)
        assert mode == 0o700, f"{ancestor} mode {oct(mode)} is not 0o700"


# --- Controller fix (b): config.yaml must never exist at a world-readable mode ---


def test_config_yaml_created_via_open_excl_mode_0o600(tmp_path: Path, monkeypatch):
    """Regression test: config.yaml must be created at 0o600 from the first
    byte on disk, not written world-readable (write_text default mode, e.g.
    0o644) and chmodded afterwards. os.open with O_EXCL and the final mode
    closes that window; O_EXCL also rules out a TOCTOU race on the path."""
    real_open = os.open
    calls = []

    def spying_open(path, flags, mode=0o777, *args, **kwargs):
        if os.fspath(path).endswith("config.yaml"):
            calls.append((flags, mode))
        return real_open(path, flags, mode, *args, **kwargs)

    monkeypatch.setattr(engagement.os, "open", spying_open)

    engagement.create(tmp_path / "acme", _cfg(), author="jimx")

    assert calls, "config.yaml was not created via os.open"
    flags, mode = calls[0]
    assert flags & os.O_EXCL, "config.yaml creation must use O_EXCL"
    assert mode == 0o600, f"config.yaml opened with mode {oct(mode)}, must be 0o600"


def test_config_yaml_final_mode_is_0o600(tmp_path: Path):
    eng = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    mode = stat.S_IMODE((eng.root / "config.yaml").stat().st_mode)
    assert mode == 0o600


# --- Controller fix (c): engagement creation must be atomic ---


def test_scope_recording_failure_rolls_back_engagement_insert(tmp_path: Path, monkeypatch):
    """db.connect uses isolation_level=None (autocommit): without an
    explicit transaction, the engagement INSERT commits before
    _record_scope runs, so a failure between them leaves an engagement row
    with no scope_version -- authorisation that can never be answered.

    Exercised directly against `_create_engagement_and_scope`, on a
    connection this test owns, so the assertion isn't hidden behind the
    directory cleanup that fix (d) performs around the full create() flow.
    """
    from hx.store import db as db_mod

    conn = db_mod.connect(tmp_path / "hx.db")
    db_mod.init_schema(conn)

    def boom(*args, **kwargs):
        raise RuntimeError("simulated failure recording scope")

    monkeypatch.setattr(engagement, "_record_scope", boom)

    with pytest.raises(RuntimeError):
        engagement._create_engagement_and_scope(
            conn, "e-test", _cfg(), "config.yaml", author="jimx", reason="x"
        )

    count = conn.execute("SELECT COUNT(*) AS n FROM engagement").fetchone()["n"]
    assert count == 0, "engagement row survived a failed scope recording"
    conn.close()


# --- Controller fix (d): create() must not strand a half-made engagement ---


def test_failed_create_leaves_no_directory_behind(tmp_path: Path, monkeypatch):
    """End-to-end companion to the fix (c) test above: going through the
    public create() with the same failure must not strand a directory (and
    therefore not an engagement row either -- the whole tree, db included,
    is gone)."""

    def boom(*args, **kwargs):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(engagement, "_record_scope", boom)

    with pytest.raises(RuntimeError):
        engagement.create(tmp_path / "acme", _cfg(), author="jimx")

    assert not (tmp_path / "acme").exists()


def test_create_succeeds_after_a_prior_failed_attempt(tmp_path: Path, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(engagement, "_record_scope", boom)
    with pytest.raises(RuntimeError):
        engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    monkeypatch.undo()

    eng = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    assert eng.root.exists()
    assert (eng.root / "hx.db").exists()


def test_failed_create_does_not_remove_a_preexisting_directory(tmp_path: Path):
    """create() must only remove a directory tree it created itself. If the
    target path already existed (e.g. a concurrent create lost the race, or
    someone hand-crafted the directory), failure must not delete it."""
    target = tmp_path / "acme"
    target.mkdir(mode=0o700)
    marker = target / "sentinel"
    marker.write_text("do not delete me")

    with pytest.raises(engagement.EngagementError, match="exists"):
        engagement.create(target, _cfg(), author="jimx")

    assert marker.exists()


# --- Fix round 1: open_() must not leak its connection on error paths ---


def test_open_closes_connection_on_failure_after_connect(tmp_path: Path, monkeypatch):
    """A failure after db.connect() succeeds (e.g. config.yaml missing) must
    not leak the connection. Relying on refcounting to eventually close it
    is not acceptable for a public API: a caller holding the exception (a
    CLI logging the traceback, pytest) keeps the handle open indefinitely.
    """
    import sqlite3

    from hx.store import db as db_mod

    engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    (tmp_path / "acme" / "config.yaml").unlink()

    captured = {}
    real_connect = db_mod.connect

    def spying_connect(path, **kwargs):
        conn = real_connect(path, **kwargs)
        captured["conn"] = conn
        return conn

    monkeypatch.setattr(db_mod, "connect", spying_connect)

    with pytest.raises(FileNotFoundError):
        engagement.open_(tmp_path / "acme")

    assert "conn" in captured, "open_() never reached db.connect()"
    with pytest.raises(sqlite3.ProgrammingError):
        captured["conn"].execute("SELECT 1")


# --- Regression test for the self-review fix: BlobStore inside create()'s try ---


def test_blobstore_construction_failure_still_triggers_cleanup(tmp_path: Path, monkeypatch):
    """Every other failure-injection test stubs `_record_scope`, which runs
    before `BlobStore(root/'blobs')` is constructed, so none of them ever
    reach that line. Without this test, a future edit that moved the
    BlobStore construction back outside create()'s try/except would leave
    fix (d) enforced there only by discipline, and the suite would stay
    green."""

    def boom(*args, **kwargs):
        raise RuntimeError("simulated BlobStore construction failure")

    monkeypatch.setattr(engagement.blobs_mod, "BlobStore", boom)

    with pytest.raises(RuntimeError):
        engagement.create(tmp_path / "acme", _cfg(), author="jimx")

    assert not (tmp_path / "acme").exists()


# --- I1: record_scope_version's config.yaml rewrite must be atomic and 0o600 ---


def test_record_scope_version_recreates_missing_config_yaml_at_0o600(tmp_path: Path):
    """record_scope_version must route through the same atomic-replace
    helper as create(): a bare write_text() on a missing file lands at the
    umask default (e.g. 0o644), not 0o600, and `_write_config_secure` sat
    unused for exactly this call site."""
    eng = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    (eng.root / "config.yaml").unlink()

    engagement.record_scope_version(eng, author="jimx", reason="rewrite after deletion")

    mode = stat.S_IMODE((eng.root / "config.yaml").stat().st_mode)
    assert mode == 0o600


def test_record_scope_version_writes_exact_dumps_output(tmp_path: Path):
    eng = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    eng.config.scope_include.append("https://api.acme.com/*")

    engagement.record_scope_version(eng, author="jimx", reason="client added API host")

    on_disk = (eng.root / "config.yaml").read_text(encoding="utf-8")
    assert on_disk == config.dumps(eng.config)


def test_record_scope_version_leaves_no_tmp_file_behind(tmp_path: Path):
    """Truncate-then-write with no temp file, no fsync, no rename meant a
    write interrupted partway left `config.yaml` as valid YAML with a
    shorter `dangerous_paths` list -- `logout` and `delete` are among the
    last entries `dumps()` emits. The fix's temp file must not survive a
    successful write either."""
    eng = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    eng.config.scope_include.append("https://api.acme.com/*")

    engagement.record_scope_version(eng, author="jimx", reason="client added API host")

    hidden = [p.name for p in eng.root.iterdir() if p.name.startswith(".")]
    assert hidden == [], f"leftover temp file(s): {hidden}"


# --- I2: config.yaml and the recorded scope of record must never diverge ---


def test_open_raises_on_hand_edited_config_yaml(tmp_path: Path):
    """A hand edit to config.yaml after create() must not silently become
    the live scope while the recorded scope_version history says something
    else. There is no legitimate hand-edit workflow in this store --
    record_scope_version is the API -- so divergence raises, it does not
    warn."""
    eng = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    eng.db.close()

    (eng.root / "config.yaml").write_text(
        "name: acme-2026-09\nclient: Acme Corp\nsafety_profile: production\n"
        "scope:\n  include: ['https://app.acme.com/*', 'https://evil.example.com/*']\n"
        "  exclude: []\nrender_allow: []\ndangerous_paths: []\nchecks: {}\n"
        "rate_limit_rps: 5\nmax_concurrency: 2\nidentities: {}\n"
        "preserve_segments: []\nslug_threshold: 12\n",
        encoding="utf-8",
    )

    with pytest.raises(engagement.EngagementError, match="diverges"):
        engagement.open_(tmp_path / "acme")


def test_open_succeeds_when_config_yaml_matches_the_recorded_scope(tmp_path: Path):
    """The normal create() -> open_() round trip must still succeed: both
    files are written from the same dumps() output at create() time."""
    created = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    created.db.close()

    reopened = engagement.open_(tmp_path / "acme")
    assert reopened.id == created.id


# --- I5: exactly one engagement row, enforced defensively in open_() too,
# not only by the schema trigger ---


def test_open_raises_when_engagement_table_has_two_rows(tmp_path: Path):
    """The schema trigger (tested in test_db.py) prevents a second row
    through normal INSERT; this proves open_() itself does not trust
    `SELECT ... LIMIT 1` with no ORDER BY, which would pick an arbitrary
    row if a second one ever got in some other way (e.g. a hand-crafted
    database, or a future migration bug)."""
    eng = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    eng.db.execute("DROP TRIGGER trg_engagement_singleton")
    eng.db.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e-rogue','globex','Globex',2,'active')"
    )
    eng.db.close()

    with pytest.raises(engagement.EngagementError, match="exactly one"):
        engagement.open_(tmp_path / "acme")


# --- I6: an engagement created by a different schema version must not open ---


def test_open_rejects_a_different_schema_version(tmp_path: Path):
    """There is no migration mechanism, so every schema gap is currently
    permanent -- silently proceeding on a version mismatch would run
    queries against tables/triggers the store does not actually have."""
    eng = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    eng.db.execute("PRAGMA user_version=99")
    eng.db.close()

    with pytest.raises(engagement.EngagementError, match="schema version"):
        engagement.open_(tmp_path / "acme")


# --- Test-suite fix: prove the spec S5 isolation/destruction guarantee ---


def test_deleting_one_engagement_does_not_affect_another(tmp_path: Path):
    """The contractual claim is that `rm -rf` of one engagement directory
    must not touch another's data. Nothing currently tests this end to
    end."""
    import shutil

    a = engagement.create(tmp_path / "acme", _cfg("acme"), author="jimx")
    b = engagement.create(tmp_path / "globex", _cfg("globex"), author="jimx")

    a.blobs.put(b"acme secret response")
    b_digest, _ = b.blobs.put(b"globex secret response")

    a.db.close()  # release the connection before nuking a's directory
    shutil.rmtree(a.root)

    assert not a.root.exists()
    assert b.blobs.get(b_digest) == b"globex secret response"
    assert b.db.execute("SELECT COUNT(*) AS n FROM engagement").fetchone()["n"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_engagement.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.engagement'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/hx/engagement.py
"""Engagement lifecycle.

The engagement is the unit of isolation: its own directory, its own database,
its own blob tree. Nothing is shared between engagements, so client A's bytes
cannot reach client B's report and contractual data destruction is a single
`rm -rf` of one directory.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from hx import config as config_mod
from hx.store import blobs as blobs_mod
from hx.store import db as db_mod
from hx.store.paths import secure_mkdir


class EngagementError(Exception):
    """The engagement directory is missing, malformed, or already present."""


def now_us() -> int:
    return time.time_ns() // 1000


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@dataclass
class Engagement:
    id: str
    root: Path
    config: config_mod.Config
    db: sqlite3.Connection
    blobs: blobs_mod.BlobStore


def _write_config_secure(path: Path, text: str) -> None:
    """Atomically replace `path` with `text`, never at a looser mode than
    0o600 and never leaving a half-written file behind.

    Used for both first creation (`create()`) and every subsequent rewrite
    (`record_scope_version()`). A bare `write_text()` -- whether creating the
    file or truncating an existing one -- has no temp file, no fsync, and no
    atomic rename: a process killed mid-write can leave `config.yaml`
    truncated, or (worse) leave it as valid YAML with every required key
    present but a shorter `dangerous_paths` list, since `dumps()` emits that
    key near the end. The blob store already does temp -> fsync -> verify ->
    `os.replace` for a response body; the file defining what is contractually
    permitted to touch gets no less.

    The temp file is created with `O_EXCL` at the final 0o600 mode, so it is
    never briefly world-readable either.
    """
    path = Path(path)
    # Hidden, uuid-qualified, but same trailing name as the target: a
    # collision-proof temp name in the same directory (so the final
    # os.replace stays on one filesystem and is atomic).
    tmp = path.parent / f".{uuid.uuid4().hex}.{path.name}"
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    # OWNERSHIP OF `fd` TRANSFERS AT THE os.fdopen BELOW, and the two
    # guards exist because it does: os.fdopen wraps the descriptor in a file
    # object that closes it -- so once this succeeds, `fd` is the file
    # object's to close and closing it here as well closes whatever number
    # the OS has handed out since.
    #
    # It used to be one `try` around both, with `os.close(fd)` in the
    # except arm. DEMONSTRATED: raise inside the `with` body and that arm
    # runs `os.close` on an already-closed descriptor -- OSError 9 (EBADF),
    # caught and shrugged off. Harmless only while nothing else opens
    # anything in that window. Demonstrated too: with one intervening
    # open() the kernel hands back THE SAME NUMBER, `os.close` then
    # succeeds, and an `fstat` on the new owner's descriptor answers EBADF.
    # The bridge's accept loop opens sockets continuously.
    try:
        fh = os.fdopen(fd, "w", encoding="utf-8")
    except BaseException:
        # It did NOT take ownership, so `fd` is still ours to close.
        os.close(fd)
        Path(tmp).unlink(missing_ok=True)
        raise
    try:
        with fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        # No os.close here: `fh` owns the descriptor and the `with` has
        # already closed it on the way out.
        Path(tmp).unlink(missing_ok=True)
        raise


def _record_scope(
    conn: sqlite3.Connection,
    engagement_id: str,
    cfg: config_mod.Config,
    *,
    author: str,
    reason: str,
) -> str:
    yaml_text = config_mod.dumps(cfg)
    sv_id = _new_id("sv")
    conn.execute(
        "INSERT INTO scope_version(id, engagement_id, yaml, sha256,"
        " effective_from_us, author, reason) VALUES(?,?,?,?,?,?,?)",
        (
            sv_id,
            engagement_id,
            yaml_text,
            hashlib.sha256(yaml_text.encode("utf-8")).hexdigest(),
            now_us(),
            author,
            reason,
        ),
    )
    return sv_id


def _create_engagement_and_scope(
    conn: sqlite3.Connection,
    eng_id: str,
    cfg: config_mod.Config,
    config_path: str,
    *,
    author: str,
    reason: str,
) -> str:
    """Insert the engagement row and its initial scope version atomically.

    `db.connect` uses `isolation_level=None` (autocommit), so without an
    explicit transaction the engagement INSERT commits immediately and a
    failure while recording scope leaves an engagement with no authorisation
    record -- exactly the state the design says must be impossible ("what
    was in scope when request X was issued" must always be answerable).
    """
    with db_mod.transaction(conn):
        conn.execute(
            "INSERT INTO engagement(id, name, client, created_us, status, config_path)"
            " VALUES(?,?,?,?,?,?)",
            (eng_id, cfg.name, cfg.client, now_us(), "active", config_path),
        )
        sv_id = _record_scope(conn, eng_id, cfg, author=author, reason=reason)
    return sv_id


def create(root: Path, cfg: config_mod.Config, *, author: str) -> Engagement:
    root = Path(root)
    if root.exists():
        raise EngagementError(f"engagement directory already exists: {root}")

    created_root = False
    conn: sqlite3.Connection | None = None
    try:
        secure_mkdir(root)
        created_root = True
        (root / "exports").mkdir(mode=0o700)

        _write_config_secure(root / "config.yaml", config_mod.dumps(cfg))

        conn = db_mod.connect(root / "hx.db")
        db_mod.init_schema(conn)

        eng_id = _new_id("e")
        _create_engagement_and_scope(
            conn,
            eng_id,
            cfg,
            str(root / "config.yaml"),
            author=author,
            reason="engagement created",
        )
        blobs = blobs_mod.BlobStore(root / "blobs")
    except Exception:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        # Only remove a directory this call actually created -- deleting one
        # we did not create is the destructive-chmod bug wearing a different
        # hat. Without this, any failure above strands the directory, and
        # every retry dies on "already exists".
        if created_root and root.exists():
            shutil.rmtree(root, ignore_errors=True)
        raise

    return Engagement(id=eng_id, root=root, config=cfg, db=conn, blobs=blobs)


def open_(root: Path) -> Engagement:
    root = Path(root)
    if not (root / "hx.db").exists():
        raise EngagementError(f"no engagement at {root}")
    conn = db_mod.connect(root / "hx.db")
    try:
        # I6: a store opened by a different (and possibly incompatible)
        # schema version must fail loudly rather than run queries against
        # tables/triggers it does not actually have. The migration runner
        # itself is a later plan's problem; this guard only refuses to
        # pretend compatibility that was never verified.
        found_version = conn.execute("PRAGMA user_version").fetchone()[0]
        if found_version != db_mod.SCHEMA_VERSION:
            raise EngagementError(
                f"engagement at {root} was created by a different version of "
                f"hx: on-disk schema version {found_version}, this hx expects "
                f"{db_mod.SCHEMA_VERSION}"
            )

        # I5: `engagement` is meant to hold exactly one row -- it is the
        # unit of isolation, and `quarantine` and every unqualified lookup
        # here presume a single authoritative id. `LIMIT 1` with no
        # `ORDER BY` would pick an arbitrary row if a second one ever got
        # in; fetch all of them and refuse to guess.
        rows = conn.execute("SELECT id FROM engagement").fetchall()
        if len(rows) != 1:
            raise EngagementError(
                f"expected exactly one engagement row in {root}, found {len(rows)}"
            )
        row = rows[0]

        config = config_mod.load(root / "config.yaml")

        # I2: config.yaml and the recorded scope of record must never be
        # allowed to silently diverge -- a hand edit to the file would
        # otherwise become the live scope while the audit history (and,
        # later, the recorded `scope_version_id` stamped on every request)
        # says something else. There is no legitimate hand-edit workflow in
        # this store: `record_scope_version` is the API, so divergence
        # raises rather than warns.
        latest_scope = conn.execute(
            "SELECT yaml FROM scope_version"
            " ORDER BY effective_from_us DESC, rowid DESC LIMIT 1"
        ).fetchone()
        if latest_scope is not None:
            on_disk = (root / "config.yaml").read_text(encoding="utf-8")
            if on_disk != latest_scope["yaml"]:
                raise EngagementError(
                    f"{root / 'config.yaml'} diverges from the recorded scope "
                    "of record: its contents do not match the latest row in "
                    "scope_version. Restore config.yaml from that row, or "
                    "re-record the change through record_scope_version()."
                )

        blobs = blobs_mod.BlobStore(root / "blobs")
    except Exception:
        # Any failure past this point (missing config.yaml, a malformed
        # config, BlobStore init) must not leak the connection -- relying on
        # refcounting to eventually close it is not acceptable for a public
        # API, since a caller holding the exception (a CLI logging the
        # traceback, pytest) keeps the handle open indefinitely.
        conn.close()
        raise
    return Engagement(id=row["id"], root=root, config=config, db=conn, blobs=blobs)


def record_scope_version(eng: Engagement, *, author: str, reason: str) -> str:
    """Append a new scope version. Never updates an existing row."""
    sv_id = _record_scope(eng.db, eng.id, eng.config, author=author, reason=reason)
    _write_config_secure(eng.root / "config.yaml", config_mod.dumps(eng.config))
    return sv_id
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_engagement.py -v`
Expected: PASS, 7 passed

- [ ] **Step 5: Commit**

```bash
git add src/hx/engagement.py tests/test_engagement.py
git commit -m "feat(engagement): isolated engagement directories with append-only scope history"
```

---

### Task 5: CLI — `hx new` and `hx info`

**Files:**
- Create: `src/hx/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `hx.config.Config`, `hx.engagement.create`, `hx.engagement.open_`
- Produces:
  - `hx.cli.main()` — click group registered as the `hx` console script
  - `hx new NAME --client CLIENT --scope PATTERN [--scope PATTERN ...] [--profile production|staging] [--root DIR]`
  - `hx info [--root DIR]`
  - `hx.cli.default_root() -> Path` — `$HX_HOME` if set, else `~/hx/engagements`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py
import contextlib
import dataclasses
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from hx import cli
from hx import engagement as eng_mod
from hx import halt as halt_mod
from hx import report
from hx import run as run_mod
from hx import scan as scan_mod
from hx import session as session_mod
from hx.checks import base as checks_base
from hx.checks import registry as registry_mod
from hx.store import records as records_mod


@pytest.fixture(autouse=True)
def no_unit_test_in_this_file_launches_a_jvm(monkeypatch):
    """NO TEST IN THIS FILE MAY REACH THE REAL `hx.session.session`.

    THE HAZARD THIS FILE ALREADY DOCUMENTS IN PROSE, NOW ENFORCED. The
    comment above `test_info_reports_drops_loudly_when_there_are_any` records
    why the `capture start` tests were moved out to `tests/test_cli_capture.py`
    -- unstubbed, they reached `session.session`, and this machine has exactly
    one jar under the default `$HX_BURP_LAB` (a 714 MB
    `burpsuite_desktop_v2026.7.3.jar`, which `find_burp_jar`'s glob matches
    exactly once), so a plain `pytest` run would have launched real Burps.
    A comment cannot stop that happening again, and it did not: Plan 6 Task 7
    gave `hx scan` a session too, and five `scan`/`report` tests here (the
    ones invoking `scan` and `report` through `CliRunner` with nothing
    stubbed) sat one registered active check away from launching five JVMs on
    every default run. Reviewer-measured, and nothing was red -- the trap
    arms itself the day `hx.active.cors` joins `registry.CHECKS`, not today.

    OPTING IN IS REPLACING IT. A test that legitimately drives the session
    path monkeypatches `cli.session_mod.session` with its own double in the
    test body, which runs after this fixture and therefore wins; `refuse`
    below is then never called and this fixture passes silently. There is no
    marker to remember, because the thing a safe test must do -- stub the
    session -- IS the opt-in.

    IT RAISES `SessionError` AND FAILS IN TEARDOWN, which is two mechanisms
    for one job and both are needed. `pytest.fail` inside the call would be
    swallowed: `CliRunner.invoke` catches every exception by default and
    files it under `result.exception`, so the guard would surface as a
    puzzling non-zero exit rather than as itself. Raising `SessionError`
    keeps the command's own error path intact (the CLI turns it into a
    `ClickException`, as it would for any session failure), and the
    post-yield `pytest.fail` then reports the real cause somewhere
    `CliRunner` cannot reach.
    """
    reached: list[str] = []

    def refuse(eng, *, instance, **kwargs):
        reached.append(instance)
        raise session_mod.SessionError(
            "tests/test_cli.py's no-JVM guard refused to launch Burp")

    monkeypatch.setattr(cli.session_mod, "session", refuse)
    yield
    if reached:
        pytest.fail(
            "this test reached the real hx.session.session (instance="
            f"{reached[0]!r}), which launches a real Burp: ~10 s and a 900 MB "
            "JVM inside the default `pytest` run. Stub "
            "`cli.session_mod.session` in the test, or move the test to "
            "tests/test_cli_capture.py, which stubs it throughout.")


def test_new_creates_engagement(tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        [
            "new", "acme-2026-09",
            "--client", "Acme Corp",
            "--scope", "https://app.acme.com/*",
            "--root", str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "acme-2026-09" / "hx.db").exists()
    assert "acme-2026-09" in result.output


def test_new_requires_a_scope(tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        ["new", "acme", "--client", "Acme", "--root", str(tmp_path)],
    )
    assert result.exit_code != 0
    assert "scope" in result.output.lower()


def test_new_refuses_to_clobber(tmp_path: Path):
    runner = CliRunner()
    args = [
        "new", "acme", "--client", "Acme",
        "--scope", "https://a/*", "--root", str(tmp_path),
    ]
    assert runner.invoke(cli.main, args).exit_code == 0
    second = runner.invoke(cli.main, args)
    assert second.exit_code != 0
    assert "exists" in second.output.lower()


def test_info_reports_engagement(tmp_path: Path):
    runner = CliRunner()
    runner.invoke(
        cli.main,
        [
            "new", "acme", "--client", "Acme Corp",
            "--scope", "https://app.acme.com/*", "--root", str(tmp_path),
        ],
    )
    result = runner.invoke(cli.main, ["info", "--root", str(tmp_path / "acme")])
    assert result.exit_code == 0, result.output
    assert "Acme Corp" in result.output
    assert "production" in result.output
    assert "https://app.acme.com/*" in result.output


def test_default_root_honours_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("HX_HOME", str(tmp_path / "custom"))
    assert cli.default_root() == tmp_path / "custom"


def test_new_rejects_empty_name(tmp_path: Path):
    """Test that hx new rejects empty NAME and creates no directory."""
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        ["new", "", "--client", "Acme", "--scope", "https://a/*", "--root", str(tmp_path)],
    )
    assert result.exit_code != 0
    # Ensure no directory was created at all
    assert len(list(tmp_path.iterdir())) == 0


def test_new_rejects_empty_client(tmp_path: Path):
    """Test that hx new rejects empty --client and creates no directory."""
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        ["new", "acme", "--client", "", "--scope", "https://a/*", "--root", str(tmp_path)],
    )
    assert result.exit_code != 0
    # Ensure no directory was created at all
    assert len(list(tmp_path.iterdir())) == 0


@pytest.mark.parametrize("option", ["--scope", "--exclude"])
def test_new_rejects_a_blank_scope_entry(tmp_path: Path, option):
    """A blank pattern is refused at `hx new`, not at the next `load()`.

    config.load() has refused a blank entry since the guard landed, but `hx new`
    does not go through load(): it builds a Config from its options and dumps()
    it. So `hx new --exclude ''` wrote `exclude: ['']` into config.yaml and into
    the scope_version row, and the operator learned about it on the next open --
    which is the one thing the guard was added to prevent. The extension still
    fails closed on an empty pattern, so this was never a bypass; it was the
    guard firing one step too late to be the guard.
    """
    runner = CliRunner()
    args = ["new", "acme", "--client", "Acme", "--scope", "https://a/*",
            "--root", str(tmp_path)]
    if option == "--scope":
        args = ["new", "acme", "--client", "Acme", "--scope", "",
                "--root", str(tmp_path)]
    else:
        args += ["--exclude", ""]
    result = runner.invoke(cli.main, args)
    assert result.exit_code != 0, result.output
    assert "blank" in result.output.lower(), result.output
    # And nothing was created: the refusal comes before any directory is made.
    assert list(tmp_path.iterdir()) == []


def test_new_still_accepts_no_exclude_at_all(tmp_path: Path):
    """The control. The guard refuses a blank ENTRY, never an empty LIST --
    `exclude: []` has to stay writable, and an operator who passes no
    `--exclude` at all is writing exactly that."""
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        ["new", "acme", "--client", "Acme", "--scope", "https://a/*",
         "--root", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    text = (tmp_path / "acme" / "config.yaml").read_text(encoding="utf-8")
    assert "exclude: []" in text


def test_info_missing_config_yaml(tmp_path: Path):
    """Test that info handles missing config.yaml gracefully."""
    runner = CliRunner()
    # Create an engagement
    result = runner.invoke(
        cli.main,
        [
            "new", "acme", "--client", "Acme Corp",
            "--scope", "https://app.acme.com/*", "--root", str(tmp_path),
        ],
    )
    assert result.exit_code == 0

    # Delete config.yaml
    config_path = tmp_path / "acme" / "config.yaml"
    config_path.unlink()

    # Try to run info - should show an error, not a traceback
    result = runner.invoke(cli.main, ["info", "--root", str(tmp_path / "acme")])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert str(tmp_path / "acme") in result.output


def test_info_malformed_config_yaml(tmp_path: Path):
    """Test that info handles malformed config.yaml gracefully."""
    runner = CliRunner()
    # Create an engagement
    result = runner.invoke(
        cli.main,
        [
            "new", "acme", "--client", "Acme Corp",
            "--scope", "https://app.acme.com/*", "--root", str(tmp_path),
        ],
    )
    assert result.exit_code == 0

    # Write malformed YAML
    config_path = tmp_path / "acme" / "config.yaml"
    config_path.write_text("{ invalid yaml: [")

    # Try to run info - should show an error, not a traceback
    result = runner.invoke(cli.main, ["info", "--root", str(tmp_path / "acme")])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert str(tmp_path / "acme") in result.output


def test_info_damaged_database(tmp_path: Path):
    """Test that info handles inaccessible database gracefully."""
    import os as os_module

    runner = CliRunner()
    # Create an engagement
    result = runner.invoke(
        cli.main,
        [
            "new", "acme", "--client", "Acme Corp",
            "--scope", "https://app.acme.com/*", "--root", str(tmp_path),
        ],
    )
    assert result.exit_code == 0

    # Make the database inaccessible
    db_path = tmp_path / "acme" / "hx.db"
    os_module.chmod(db_path, 0o000)

    try:
        # Try to run info - should show an error, not a traceback
        result = runner.invoke(cli.main, ["info", "--root", str(tmp_path / "acme")])
        assert result.exit_code != 0
        assert "Traceback" not in result.output
    finally:
        # Restore permissions so pytest can clean up
        os_module.chmod(db_path, 0o600)


# --- I3: `hx new` accepts a path, not a name ---


@pytest.mark.parametrize("bad_name", [".", "..", "../escaped", "a/b"])
def test_new_rejects_path_like_names_within_root(tmp_path: Path, bad_name):
    """`.` breaks the destruction guarantee outright (the engagements root
    itself becomes an engagement, so `rm -rf` of it destroys every sibling
    client), and any other traversal walks the created directory outside
    the engagements root. Nothing must be created at all."""
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        ["new", bad_name, "--client", "Acme", "--scope", "https://a/*", "--root", str(tmp_path)],
    )
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert list(tmp_path.iterdir()) == [], f"NAME={bad_name!r} created something under root"


def test_new_rejects_an_absolute_path_as_name(tmp_path: Path):
    """pathlib's `/` operator discards the left operand when the right one
    is absolute, so NAME='/tmp/hx-i3-abs-escape-test' used to make --root
    silently ignored and create the engagement at that literal absolute
    path."""
    target = Path("/tmp/hx-i3-abs-escape-test")
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)

    runner = CliRunner()
    try:
        result = runner.invoke(
            cli.main,
            [
                "new", str(target), "--client", "Acme",
                "--scope", "https://a/*", "--root", str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "Traceback" not in result.output
        assert not target.exists(), "NAME as an absolute path escaped --root entirely"
        assert list(tmp_path.iterdir()) == []
    finally:
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)


def test_new_accepts_a_normal_name(tmp_path: Path):
    """The validation must not be so strict it rejects ordinary names."""
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        [
            "new", "acme-2026-09.retest_1", "--client", "Acme",
            "--scope", "https://a/*", "--root", str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "acme-2026-09.retest_1" / "hx.db").exists()


# --- M3: `hx new` must degrade like `hx info` does, not traceback ---


def test_new_reports_a_clean_error_when_root_is_not_a_directory(tmp_path: Path):
    """`hx new acme --root /etc/hostname` used to dump a NotADirectoryError
    traceback -- `new` needs the same guard shape `info` already has."""
    not_a_dir = tmp_path / "im-a-file"
    not_a_dir.write_text("not a directory")

    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        [
            "new", "x", "--client", "Acme",
            "--scope", "https://a/*", "--root", str(not_a_dir),
        ],
    )
    assert result.exit_code != 0
    assert "Traceback" not in result.output


# --- Task 8: `hx capture start/stop`, and `hx info` that admits its gaps ---


@pytest.fixture
def engagement(tmp_path: Path) -> Path:
    """A real engagement, made the way an operator makes one.

    Returns the ENGAGEMENT directory itself (`tmp_path / name`), not the
    engagements root `new --root` takes. `info` and `capture` both open a
    single engagement directly (`eng_mod.open_` checks for `hx.db` right at
    the path it is given), the same way `test_info_reports_engagement` above
    passes `tmp_path / "acme"` -- the child directory, never `tmp_path`
    itself -- to `info --root`.
    """
    result = CliRunner().invoke(cli.main, [
        "new", "acme-2026-09", "--client", "Acme Corp",
        "--scope", "https://app.acme.com/*", "--root", str(tmp_path),
    ])
    assert result.exit_code == 0, result.output
    return tmp_path / "acme-2026-09"


@pytest.fixture
def engagement_with_drops(engagement: Path) -> Path:
    """A run recorded 4 dropped exchanges, through `hx.run`, not raw SQL."""
    eng = eng_mod.open_(engagement)
    try:
        run_id = run_mod.open_run(
            eng.db, engagement_id=eng.id, kind="browse",
            safety_profile=eng.config.safety_profile)
        run_mod.count_drop(eng.db, run_id=run_id, n=4)
    finally:
        eng.db.close()
    return engagement


@pytest.fixture
def engagement_with_stale_run(engagement: Path) -> Path:
    """A run whose heartbeat is old enough for `reap_stale` to find it.

    `reap_stale`'s own default window is `IDLE_CLOSE_US * 2`, not
    `IDLE_CLOSE_US` -- the two windows are deliberately different (idle vs.
    dead-harness), per `run.reap_stale`'s docstring. Backdating by a single
    `IDLE_CLOSE_US` would not clear reap_stale's own default threshold, so
    this backdates well past it.
    """
    eng = eng_mod.open_(engagement)
    try:
        run_id = run_mod.open_run(
            eng.db, engagement_id=eng.id, kind="browse",
            safety_profile=eng.config.safety_profile)
        stale_at = eng_mod.now_us() - (run_mod.IDLE_CLOSE_US * 3)
        run_mod.heartbeat(eng.db, run_id=run_id, now_us=stale_at)
    finally:
        eng.db.close()
    return engagement


# Task 7 rewired `hx capture start` so it actually launches Burp (through
# `session.session`), which means it now blocks for the life of the session
# and a plain unstubbed `CliRunner` invocation is no longer safe in the
# default suite -- this machine has exactly one jar under the default
# `$HX_BURP_LAB`, so `find_burp_jar` would find it and launch a real Burp.
# The `capture start`/`capture stop` tests that used to live here moved to
# tests/test_cli_capture.py, which stubs `session.session` throughout; the
# fixtures below (`engagement` and its variants) stay because the `info` and
# `scan`/`report` tests further down still use them.
#
# THAT MOVE IS NO LONGER THE ONLY THING HOLDING THE LINE. Task 7 of Plan 6
# gave `hx scan` a session as well, and this comment did not stop five tests
# below from re-arming the same trap. `no_unit_test_in_this_file_launches_a_jvm`
# at the top of the file is the autouse guard that now enforces the rule for
# every test here, whatever command it invokes.


def test_info_reports_drops_loudly_when_there_are_any(engagement_with_drops):
    """S5: a run with drops has coverage numbers that are a FLOOR, not a
    count. An operator who does not know that reads the surface count as
    complete."""
    result = CliRunner().invoke(cli.main, ["info", "--root", str(engagement_with_drops)])
    assert "floor" in result.output.lower()
    # The COUNT, in its own context. A bare `"4" in output` passes on any
    # unrelated 4 -- four surfaces, a timestamp digit -- which is the shape of
    # a test that reads green for the wrong reason.
    assert "4 dropped" in result.output


def test_info_says_nothing_alarming_when_there_are_no_drops(engagement):
    """The separating case. A warning that is always present is not a
    warning."""
    result = CliRunner().invoke(cli.main, ["info", "--root", str(engagement)])
    assert "floor" not in result.output.lower()


def test_info_reaps_stale_runs_before_reporting(engagement_with_stale_run):
    """Otherwise the first thing an operator sees after a crash is a run that
    claims to be running."""
    result = CliRunner().invoke(cli.main, ["info", "--root", str(engagement_with_stale_run)])
    assert "error" in result.output.lower()


# `test_capture_start_is_idempotent`, F1
# (`test_capture_stop_writes_completed_status_and_operator_reason`) and F2
# (`test_capture_stop_with_kind_only_closes_that_kind`) moved to
# tests/test_cli_capture.py along with the rest of the `capture`
# start/stop family -- see the note above `test_info_reports_drops_loudly...`.


@pytest.fixture
def engagement_with_drops_on_two_runs(engagement: Path) -> Path:
    """Two DIFFERENT runs, each with its own nonzero drop count, so the
    printed total can be told apart from a single run's count, a MAX, or a
    last-value written -- none of which `engagement_with_drops` (one run)
    can separate from a correct SUM."""
    eng = eng_mod.open_(engagement)
    try:
        r1 = run_mod.open_run(
            eng.db, engagement_id=eng.id, kind="browse",
            safety_profile=eng.config.safety_profile)
        run_mod.count_drop(eng.db, run_id=r1, n=4)
        r2 = run_mod.open_run(
            eng.db, engagement_id=eng.id, kind="crawl",
            safety_profile=eng.config.safety_profile)
        run_mod.count_drop(eng.db, run_id=r2, n=7)
    finally:
        eng.db.close()
    return engagement


def test_info_floor_count_sums_drops_across_every_run(engagement_with_drops_on_two_runs):
    """F3: Q1 in the review asks exactly this -- is the printed total a SUM
    across runs, or could it be one run's count? `engagement_with_drops`
    only ever makes one run, so it cannot tell a sum (11) from a max (7) or
    a last-value (whichever ran last). This fixture makes two, 4 and 7, and
    the only correct total is their sum, 11."""
    result = CliRunner().invoke(
        cli.main, ["info", "--root", str(engagement_with_drops_on_two_runs)])
    assert result.exit_code == 0, result.output
    assert "floor" in result.output.lower()
    assert "11 dropped" in result.output


def test_info_breakdown_lines_report_their_own_table(engagement):
    """F4: each of the three breakdown lines must carry ITS OWN table's
    counts under its own heading. A row is planted in each of surface,
    exchange and denial with a value unique to that table (no vocabulary
    overlaps another table's), so a swapped table argument -- e.g. printing
    denial counts under 'surfaces' -- is caught by checking each heading's
    OWN line, not by a bare substring search of the whole page (which would
    pass even with the values filed under the wrong heading)."""
    eng = eng_mod.open_(engagement)
    try:
        eng.db.execute(
            "INSERT INTO surface(id, engagement_id, method, scheme, host,"
            " port, path_template, kind, discovered_by, normaliser_version)"
            " VALUES('s1', ?, 'GET', 'https', 'app.acme.com', 443,"
            " '/api/widgets', 'state_changing', 'proxy', 1)",
            (eng.id,))
        records_mod.record_exchange(
            eng.db, run_id=None, method="GET", url="https://app.acme.com/x",
            status=None, req_blob=None, resp_blob=None, ms=0,
            at_us=eng_mod.now_us(), outcome="timeout")
        records_mod.record_denial(
            eng.db, run_id=None, kind="rate", method="GET",
            url="https://app.acme.com/y", detail="over budget",
            at_us=eng_mod.now_us())
    finally:
        eng.db.close()

    result = CliRunner().invoke(cli.main, ["info", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    surfaces_line = next(ln for ln in lines if ln.strip().startswith("surfaces"))
    exchanges_line = next(ln for ln in lines if ln.strip().startswith("exchanges"))
    denials_line = next(ln for ln in lines if ln.strip().startswith("denials"))

    assert "state_changing=1" in surfaces_line
    assert "rate=1" not in surfaces_line
    assert "timeout=1" not in surfaces_line

    assert "timeout=1" in exchanges_line
    assert "state_changing=1" not in exchanges_line
    assert "rate=1" not in exchanges_line

    assert "rate=1" in denials_line
    assert "state_changing=1" not in denials_line
    assert "timeout=1" not in denials_line


# --- B5: `hx halt` / `hx resume`, S4's kill switch reachable by a human -----


def _halt_state(engagement: Path):
    """Read the halt back through a FRESH OperatorHalt, the way the harness
    and the next process do. Reading the CLI's own object would only prove it
    remembered its own call; the whole point of a durable halt is that another
    process sees it."""
    eng = eng_mod.open_(engagement)
    try:
        oh = halt_mod.OperatorHalt(eng.root, eng.db)
        return oh.halted, oh.reason, oh.sentinel_path
    finally:
        eng.db.close()


def test_halt_stops_issuance_and_writes_the_file_the_extension_polls(engagement):
    """S4's third kill path, reachable by a person for the first time.

    Two of the three §4 promises had no way in: `BridgeServer.halt()` and
    `resume()` are correct and durable and had no CLI and no production
    driver, and the suite-tab STOP button is unbuilt. Only "create the
    sentinel by hand" was something an operator could do -- and §4's whole
    argument is the redundancy, not any one path.

    THE FILE IS THE ASSERTION. `-Dhx.halt_sentinel` is what the extension
    polls, and `burp_fixture.launch_burp` passes `OperatorHalt.sentinel_path`
    for it -- so a CLI that stopped issuance by some other means would report
    success while the extension kept sending.
    """
    result = CliRunner().invoke(cli.main, [
        "halt", "--reason", "the client asked us to stop",
        "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    halted, reason, sentinel = _halt_state(engagement)
    assert halted is True
    assert reason == "the client asked us to stop"
    assert sentinel == engagement / "HALTED"
    assert sentinel.exists()
    assert "the client asked us to stop" in result.output
    assert str(sentinel) in result.output


def test_halt_writes_the_audit_row_as_well_as_the_file(engagement):
    """Durable is the row AND the file: the file is what stops the extension,
    the row is what explains the stop afterwards. A halt nobody can account
    for at the end of an engagement is the half `agent_action` exists for."""
    CliRunner().invoke(cli.main, [
        "halt", "--reason", "target wobbling", "--root", str(engagement)])
    eng = eng_mod.open_(engagement)
    try:
        rows = eng.db.execute(
            "SELECT actor, tool, why FROM agent_action ORDER BY ts_us"
        ).fetchall()
    finally:
        eng.db.close()
    assert [(r["actor"], r["tool"]) for r in rows] == [("operator", "halt")]
    assert rows[0]["why"] == "target wobbling"


def test_halt_needs_no_reason_because_it_is_a_kill_switch(engagement):
    """`--reason` is OPTIONAL on purpose, and this pins the decision. The
    moment this command is used is the moment something is going wrong on a
    client's production system; a required argument is friction in front of a
    stop. What is NOT optional is that the recorded reason still says who
    stopped it and how, which is the part nobody can reconstruct later."""
    result = CliRunner().invoke(cli.main, ["halt", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    halted, reason, _ = _halt_state(engagement)
    assert halted is True
    assert "command line" in reason


def test_resume_is_the_only_thing_that_lifts_it(engagement):
    CliRunner().invoke(cli.main, [
        "halt", "--reason", "stop", "--root", str(engagement)])
    result = CliRunner().invoke(cli.main, ["resume", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    halted, reason, sentinel = _halt_state(engagement)
    assert halted is False
    assert reason is None
    assert not sentinel.exists()
    assert "stop" in result.output


def test_resume_clears_a_sentinel_nobody_recorded(engagement):
    """§4 names the by-hand path explicitly -- an operator can `touch` the
    sentinel from a shell when the socket is dead -- and such a halt has no
    row behind it. `OperatorHalt.halted` is a UNION for that reason, and this
    is the case that would strand an engagement halted forever if `resume`
    consulted the row instead."""
    (engagement / "HALTED").write_text("stopped by hand at 02:00\n")
    result = CliRunner().invoke(cli.main, ["resume", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert not (engagement / "HALTED").exists()
    assert _halt_state(engagement)[0] is False


def test_resume_on_an_un_halted_engagement_writes_nothing(engagement):
    """An audit trail whose entries do not correspond to events is worse than
    a short one, and `resume()` would append a resume row for a stop that
    never happened. Refusing is safe here rather than pedantic: the direction
    that matters is that nothing accidentally re-arms issuance."""
    result = CliRunner().invoke(cli.main, ["resume", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert "nothing to resume" in result.output
    eng = eng_mod.open_(engagement)
    try:
        assert eng.db.execute(
            "SELECT COUNT(*) AS n FROM agent_action").fetchone()["n"] == 0
    finally:
        eng.db.close()


def test_halting_an_already_halted_engagement_says_so_and_still_halts(engagement):
    """Idempotent, and it SAYS what it found. An operator typing `halt` twice
    during an incident must not be told nothing happened, and must not be left
    wondering whether the second reason replaced the first."""
    CliRunner().invoke(cli.main, [
        "halt", "--reason", "first reason", "--root", str(engagement)])
    result = CliRunner().invoke(cli.main, [
        "halt", "--reason", "second reason", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert "already halted: first reason" in result.output
    halted, reason, _ = _halt_state(engagement)
    assert halted is True
    assert reason == "second reason"


def test_info_says_so_when_issuance_is_halted(engagement):
    """Where an operator looks first. §4 makes the sentinel something a
    DIFFERENT person can create from a shell with no harness running, so an
    operator can arrive at a halted engagement they did not halt -- and until
    this line nothing in the CLI would tell them."""
    before = CliRunner().invoke(cli.main, ["info", "--root", str(engagement)])
    assert "HALTED" not in before.output, (
        "the halt line must appear only when there IS one, or it stops "
        "meaning anything")
    CliRunner().invoke(cli.main, [
        "halt", "--reason", "the client asked us to stop",
        "--root", str(engagement)])
    after = CliRunner().invoke(cli.main, ["info", "--root", str(engagement)])
    assert after.exit_code == 0, after.output
    assert "HALTED" in after.output
    assert "the client asked us to stop" in after.output
    assert "hx resume" in after.output


@pytest.mark.parametrize("command", [["halt"], ["resume"]])
def test_both_refuse_cleanly_when_there_is_no_engagement(tmp_path, command):
    """`hx capture`'s shape: a missing engagement is a ClickException with a
    sentence in it, never a traceback. A kill switch that answers with a
    stack trace is one an operator does not trust the next time."""
    result = CliRunner().invoke(cli.main, command + ["--root", str(tmp_path)])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert "no engagement" in result.output.lower()


def test_deleting_the_sentinel_by_hand_leaves_the_two_sides_disagreeing(engagement):
    """THE CLAIM I HAD WRONG, as a check rather than a sentence.

    `hx resume`'s docstring said it was "the only thing that lifts a halt".
    It is not. The extension polls the sentinel FILE and nothing else -- which
    is exactly what S4 asks of it, "an operator can create it from a shell when
    the socket is dead" -- and a mechanism that can be created by hand can be
    removed by hand.

    What that loses is asserted here: no `agent_action` row says the halt was
    lifted, and a process that reads the store still believes issuance is
    stopped while the extension has already started again. The two sides
    disagree, and the disagreement is silent. `hx resume` is what leaves them
    agreeing and leaves a row behind.
    """
    CliRunner().invoke(cli.main, [
        "halt", "--reason", "stop", "--root", str(engagement)])
    (engagement / "HALTED").unlink()

    halted, reason, _ = _halt_state(engagement)
    assert halted is True, (
        "the store no longer believes this engagement is halted, so the "
        "disagreement this test documents does not exist and `hx resume`'s "
        "docstring should say so")
    assert reason == "stop"

    eng = eng_mod.open_(engagement)
    try:
        tools = [r["tool"] for r in eng.db.execute(
            "SELECT tool FROM agent_action ORDER BY ts_us")]
    finally:
        eng.db.close()
    assert tools == ["halt"], (
        "removing the file by hand wrote a resume row, which would make it "
        "equivalent to `hx resume` and this whole test pointless")

    # And `hx resume` still works from here -- it is the way back to two sides
    # agreeing, and it does not require the file it is about to remove.
    result = CliRunner().invoke(cli.main, ["resume", "--root", str(engagement)])
    assert result.exit_code == 0, result.output
    assert _halt_state(engagement)[0] is False


# --- Task 7: `hx scan` ---


@pytest.fixture
def engagement_with_surface(engagement: Path) -> Path:
    """One `surface` row and one `exchange` against it, so a passive check --
    or, since Task 8, `hx.active.cors` on its `probes` hook -- has something
    to read. Built on `engagement` the way `engagement_with_drops` and
    `engagement_with_stale_run` are, per P2: this fixture did not exist
    before Task 7."""
    eng = eng_mod.open_(engagement)
    try:
        eng.db.execute(
            "INSERT INTO surface(id, engagement_id, method, scheme, host,"
            " port, path_template, discovered_by, normaliser_version)"
            " VALUES('s1', ?, 'GET', 'https', 'app.acme.com', 443,"
            " '/api/widgets', 'proxy', 1)",
            (eng.id,))
        records_mod.record_exchange(
            eng.db, run_id=None, method="GET",
            url="https://app.acme.com/api/widgets", status=200,
            req_blob=None, resp_blob=None, ms=0, at_us=eng_mod.now_us(),
            outcome="ok", surface_id="s1")
    finally:
        eng.db.close()
    return engagement


def _disable_checks(engagement_path: Path, **overrides: bool) -> None:
    """Overlay `overrides` onto an engagement's `checks` config, on disk.

    Not a raw rewrite of `config.yaml`: `eng_mod.open_`'s I2 guard refuses a
    file that has drifted from the latest `scope_version` row, so
    `record_scope_version` -- the sanctioned writer, which updates both -- is
    what a test needing a non-default `checks` map has to go through instead.
    """
    eng = eng_mod.open_(engagement_path)
    try:
        eng.config = dataclasses.replace(
            eng.config, checks={**eng.config.checks, **overrides})
        eng_mod.record_scope_version(
            eng, author="test", reason="test override of checks config")
    finally:
        eng.db.close()


def _stub_session(monkeypatch, bridge=None) -> None:
    """Stand in for `hx.session.session` with something that never launches
    a JVM, for a test whose point has nothing to do with the session itself.

    `hx.active.cors` shipping (Task 8) means `active_safe` -- on by default
    -- now has a check in it, so `hx scan` opens a session for any engagement
    with a surface (see `cli.scan`'s `sending` gate). `bridge` defaults to a
    bare `object()`: `Cors.probes` calling `.send()` on it raises
    `AttributeError`, which `scan.run`'s per-check `except Exception` turns
    into an `error` check_run row rather than a crash -- fine for every test
    below that is not itself asserting something about CORS's own outcome.
    """
    def fake(eng, *, instance, jar=None, workdir=None, seed=None):
        return contextlib.nullcontext(
            SimpleNamespace(operator_port=1, crawler_port=2, epoch=1,
                            bridge=bridge if bridge is not None else object(),
                            workdir=None, proc=None))
    monkeypatch.setattr(cli.session_mod, "session", fake)


def test_scan_reports_what_it_ran(engagement_with_surface, monkeypatch):
    _stub_session(monkeypatch)
    result = CliRunner().invoke(cli.main,
                                ["scan", "--root", str(engagement_with_surface)])
    assert result.exit_code == 0, result.output
    assert "surfaces" in result.output.lower()


_FLAGLESS_COOKIE_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Set-Cookie: session=abc; Path=/\r\n"
    b"\r\n"
)


def test_scan_prints_the_number_of_findings_the_store_holds(engagement,
                                                             monkeypatch):
    """D3 of the fix-round-A re-review. Forty surfaces of ONE host, all
    setting one flagless cookie: `cookie_flags` is `scope_level='host'`, so
    F3 of the whole-branch review makes the forty candidates land on ONE
    finding row, and the line an operator reads has to say so.

    WOULD THIS FAIL IF THE CLAIM WERE FALSE? MEASURED against the
    per-candidate counter: `findings  40` printed while `SELECT COUNT(*)
    FROM finding` was 1 -- the exact forty tickets F3 exists to prevent,
    removed from the report and left at the terminal. Forty rather than two
    because a number that is wrong by one is a number someone argues about.
    """
    eng = eng_mod.open_(engagement)
    try:
        digest, length = eng.blobs.put(_FLAGLESS_COOKIE_RESPONSE)
        for n in range(40):
            eng.db.execute(
                "INSERT INTO surface(id, engagement_id, method, scheme, host,"
                " port, path_template, discovered_by, normaliser_version)"
                " VALUES(?, ?, 'GET', 'https', 'app.acme.com', 443, ?,"
                " 'proxy', 1)",
                (f"s{n}", eng.id, f"/p{n}"))
            records_mod.record_exchange(
                eng.db, run_id=None, method="GET",
                url=f"https://app.acme.com/p{n}", status=200,
                req_blob=None, resp_blob=digest, resp_len=length, ms=0,
                at_us=eng_mod.now_us(), outcome="ok", surface_id=f"s{n}")
    finally:
        eng.db.close()

    _stub_session(monkeypatch)
    result = CliRunner().invoke(cli.main, ["scan", "--root", str(engagement)])

    assert result.exit_code == 0, result.output
    assert "findings  1" in result.output, result.output
    eng = eng_mod.open_(engagement)
    try:
        held = eng.db.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
    finally:
        eng.db.close()
    assert held == 1, (
        "the line the operator reads and the rows the report renders "
        "disagreed")


def test_scan_names_a_class_that_is_enabled_but_ships_no_checks(
        engagement_with_surface, monkeypatch):
    """config.DEFAULT_CHECKS turns `active_timing` ON by default and this
    build ships no checks in it (`active_safe` -- since Task 8 -- and
    `active_timing` are two different classes). An operator reading
    `active_timing: enabled` and seeing no rows would reasonably conclude it
    ran and found nothing. The scan says so out loud instead."""
    _stub_session(monkeypatch)
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


def test_scan_max_seconds_reaches_the_runner(engagement_with_surface, monkeypatch):
    """Row C of the sweep: none of the tests above ever pass `--max-seconds`,
    so a CLI that silently dropped it in favour of `max_seconds=None` on the
    call to `scan.run` would leave every test above green. A deadline already
    in the past is the input that separates 'wired through' from 'ignored' --
    it only truncates the scan if the CLI's own option actually reaches
    `scan.run`. `time.monotonic` is patched the same way
    `test_budget_exhaustion_writes_skipped_rows_for_the_remaining_surfaces`
    in `tests/test_scan.py` does it: one call to compute the deadline, one
    call for the single surface `engagement_with_surface` seeds."""
    _stub_session(monkeypatch)
    ticks = iter([0.0, 1.0])
    monkeypatch.setattr(scan_mod.time, "monotonic", lambda: next(ticks))
    result = CliRunner().invoke(cli.main, [
        "scan", "--root", str(engagement_with_surface), "--max-seconds", "0",
    ])
    assert result.exit_code == 0, result.output
    assert "surfaces  0" in result.output
    assert "skipped" in result.output.lower()


# --- Task 6: --max-requests -------------------------------------------------


def test_scan_max_requests_flag_overrides_the_configured_budget(
        engagement_with_surface, monkeypatch):
    """`--max-requests` overrides `eng.config.max_requests` for this
    invocation only -- the number `scan.run` is actually called with, not
    what `config.yaml` says on disk. A CLI that silently dropped the flag
    (or wrote it back to the file) would leave this test red."""
    real_run = scan_mod.run
    seen: list = []

    def fake_run(conn, *, engagement_id, blobs, config, checks=None,
                surface_filter=None, max_seconds=None, bridge=None):
        # `bridge=None` is not decoration: `hx scan` passes it the moment an
        # active check ships, and a double whose signature lags the function
        # it doubles fails with `unexpected keyword argument` rather than
        # with anything about budgets.
        seen.append(config.max_requests)
        return real_run(conn, engagement_id=engagement_id, blobs=blobs,
                        config=config, checks=checks,
                        surface_filter=surface_filter, max_seconds=max_seconds,
                        bridge=bridge)

    monkeypatch.setattr(scan_mod, "run", fake_run)
    _stub_session(monkeypatch)
    before = eng_mod.open_(engagement_with_surface)
    try:
        before_max_requests = before.config.max_requests
    finally:
        before.db.close()

    result = CliRunner().invoke(cli.main, [
        "scan", "--root", str(engagement_with_surface),
        "--max-requests", "17"])

    assert result.exit_code == 0, result.output
    assert seen == [17]
    after = eng_mod.open_(engagement_with_surface)
    try:
        assert after.config.max_requests == before_max_requests, (
            "the flag rewrote config.yaml; it must override this run only")
    finally:
        after.db.close()


def test_scan_max_requests_below_one_is_a_bad_parameter_not_a_silent_clamp(
        engagement_with_surface):
    result = CliRunner().invoke(cli.main, [
        "scan", "--root", str(engagement_with_surface),
        "--max-requests", "0"])
    assert result.exit_code != 0
    assert "max-requests" in result.output.lower()


# --- Plan 6 Task 7: `hx scan` opens the session, and only when it must -----
#
# NO REAL BURP IN THIS FILE. `session_mod.session` is replaced throughout;
# the real launch is `tests/integration/`'s, which is the only place in this
# repository allowed to cost a JVM.


class _CliActive:
    """A registerable `active_safe` check. `insertion_kinds` is empty for the
    same reason `hx.checks.active.cors`'s is -- it shapes its own request --
    which also means it runs against `engagement_with_surface`'s exchange,
    whose `req_blob` is NULL and yields no points to derive."""
    id, version, klass = "hx.test.cliactive", "1", "active_safe"
    looks_for = "a category this test invented"
    insertion_kinds = frozenset()

    def probes(self, ctx, surface, insertions, send):
        return checks_base.Verdict.clean(considered=("probed",))


def _register_active(monkeypatch):
    """Put one active check in the shipped corpus for the length of a test.

    `registry.CHECKS` rather than a stub of `registry.enabled`: `cli.scan`
    and `scan.run` both call `enabled`, and patching the tuple they both
    read keeps the two answers the same. `validate` is called on it first --
    if this shape were not one the registry accepts, the test would be
    proving the CLI drives something that can never ship."""
    check = _CliActive()
    registry_mod.validate((check,))
    monkeypatch.setattr(registry_mod, "CHECKS", registry_mod.CHECKS + (check,))
    return check


def _fake_session(opened, bridge):
    @contextlib.contextmanager
    def fake(eng, *, instance, jar=None, workdir=None, seed=None):
        opened.append(instance)
        yield SimpleNamespace(operator_port=1, crawler_port=2, epoch=1,
                              bridge=bridge, workdir=None, proc=None)
    return fake


def test_scan_opens_no_session_when_the_corpus_is_passive_only(
        engagement_with_surface, monkeypatch):
    """A passive scan stays offline. Burp costs ~10 s to start, so an engine
    nothing will send through must not be paid for.

    `active_safe` is ON by default and, since Task 8, ships a check
    (`hx.active.cors`) -- so this scenario is no longer the shipped build's
    ambient state and has to be built by hand: everything active turned off,
    leaving a corpus that is passive-only BY CONSTRUCTION rather than by
    accident of what this build happened to ship."""
    _disable_checks(engagement_with_surface, active_safe=False,
                    active_timing=False)

    def refuse(*a, **k):
        pytest.fail("a passive-only scan launched Burp")

    monkeypatch.setattr(cli.session_mod, "session", refuse)
    result = CliRunner().invoke(
        cli.main, ["scan", "--root", str(engagement_with_surface)])
    assert result.exit_code == 0, result.output


def test_scan_opens_a_session_when_an_active_check_is_enabled(
        engagement_with_surface, monkeypatch):
    """And hands `scan.run` that session's bridge. Opening a Burp and then
    scanning without its bridge would be the worst of both: the startup cost
    paid, and every active row still `skipped` for want of a route."""
    _register_active(monkeypatch)
    opened, bridge = [], object()
    monkeypatch.setattr(cli.session_mod, "session",
                        _fake_session(opened, bridge))

    seen = {}
    real_run = scan_mod.run

    def spy(conn, **kwargs):
        seen["bridge"] = kwargs.get("bridge")
        return real_run(conn, **kwargs)

    monkeypatch.setattr(scan_mod, "run", spy)
    result = CliRunner().invoke(
        cli.main, ["scan", "--root", str(engagement_with_surface)])

    assert result.exit_code == 0, result.output
    assert opened == ["scan"], "the session was not opened once, as `scan`"
    assert seen["bridge"] is bridge


def test_scan_does_not_open_a_session_for_an_active_class_that_ships_nothing(
        engagement_with_surface, monkeypatch):
    """THE SEPARATING CASE for the test above. `active_timing` is enabled by
    default and this build ships no check in it, so a CLI that tested
    `config.checks` instead of `registry.enabled` would launch a Burp for
    every scan, send nothing through it, and print the `ships no checks`
    note underneath.

    `active_safe` turned off here so `hx.active.cors` -- a class this build
    DOES ship a check in, since Task 8 -- cannot itself be the reason a
    session opens and mask what this test is actually pinning."""
    _disable_checks(engagement_with_surface, active_safe=False)

    def refuse(*a, **k):
        pytest.fail("a class with no checks in it launched Burp")

    monkeypatch.setattr(cli.session_mod, "session", refuse)
    result = CliRunner().invoke(
        cli.main, ["scan", "--root", str(engagement_with_surface)])
    assert result.exit_code == 0, result.output
    assert "ships no checks" in result.output


def test_scan_does_not_open_a_session_for_a_non_passive_class_that_reads(
        engagement_with_surface, monkeypatch):
    """FIX ROUND 1 (LOW): the gate used to be `c.klass != "passive"`, and
    this is the disagreement nothing pinned.

    `_HOOKS` decides PER CLASS which hooks are legal, and nothing says a
    non-passive class must get `probes`. Simulated here by giving
    `active_timing` the passive pairing -- a decision a later plan could
    genuinely make for a class that reads timing off captured exchanges
    rather than issuing its own -- and registering a check that implements
    `on_surface`. `registry.validate` accepts it, `scan.run` dispatches it to
    `on_surface` and sends nothing, and the old class-string gate would have
    started a 10-second JVM per scan to hand it no traffic.

    THE ASSERTION IS THE AUTOUSE GUARD. `no_unit_test_in_this_file_launches_a_jvm`
    fails this test in teardown if the gate opens a session, which is the
    same mechanism protecting every other test in the file rather than a
    second one invented here.

    `active_safe` turned off so `hx.active.cors` -- which DOES send, since
    Task 8 -- is not itself the reason a session opens here; this test is
    about `active_timing`'s hook, not about `active_safe`'s content."""
    _disable_checks(engagement_with_surface, active_safe=False)
    monkeypatch.setitem(registry_mod._HOOKS, "active_timing",
                        ("on_surface", "on_corpus"))

    class ReadsOnly:
        id, version, klass = "hx.test.reads", "1", "active_timing"
        looks_for = "a category this test invented"
        insertion_kinds = frozenset()

        def on_surface(self, ctx, surface, exchanges):
            return checks_base.Verdict.clean(considered=("read",))

    check = ReadsOnly()
    registry_mod.validate((check,))
    monkeypatch.setattr(registry_mod, "CHECKS", registry_mod.CHECKS + (check,))

    result = CliRunner().invoke(
        cli.main, ["scan", "--root", str(engagement_with_surface)])
    assert result.exit_code == 0, result.output


def test_scan_turns_a_session_error_into_a_click_exception(
        engagement_with_surface, monkeypatch):
    """The message intact, as `capture start` does. Every `SessionError`
    already names the fix -- a stale socket to remove by hand, an extension
    jar that is unbuilt -- and an operator who gets `Error: SessionError`
    instead has been handed the exception's type in place of its advice."""
    _register_active(monkeypatch)

    def die(*a, **k):
        raise session_mod.SessionError(
            "the bridge could not start on /x/hx.sock: address in use")

    monkeypatch.setattr(cli.session_mod, "session", die)
    result = CliRunner().invoke(
        cli.main, ["scan", "--root", str(engagement_with_surface)])
    assert result.exit_code != 0
    assert "the bridge could not start on /x/hx.sock" in result.output


def test_scan_max_requests_still_reaches_an_active_session(
        engagement_with_surface, monkeypatch):
    """`--max-requests` predates the session and must survive it. The number
    goes into `eng.config` before the session is opened, so it is the budget
    `session.config_body` authorises the extension with -- not just the one
    `scan.run` is handed."""
    _register_active(monkeypatch)
    seen = {}

    @contextlib.contextmanager
    def fake(eng, *, instance, jar=None, workdir=None, seed=None):
        seen["max_requests"] = eng.config.max_requests
        yield SimpleNamespace(operator_port=1, crawler_port=2, epoch=1,
                              bridge=object(), workdir=None, proc=None)

    monkeypatch.setattr(cli.session_mod, "session", fake)
    result = CliRunner().invoke(cli.main, [
        "scan", "--root", str(engagement_with_surface),
        "--max-requests", "23"])
    assert result.exit_code == 0, result.output
    assert seen["max_requests"] == 23


def test_scan_passes_its_burp_jar_to_the_session(
        engagement_with_surface, monkeypatch, tmp_path):
    """F6 of the whole-branch review. `hx scan` opens a Burp on every
    default-configured run now, and had no `--burp-jar`: an operator with two
    jars in `$HX_BURP_LAB` and no `$HX_BURP_JAR` could not scan at all,
    because `find_burp_jar` refuses to guess between them on purpose -- the
    report records the version under test.

    Asserted by IDENTITY at the session boundary, not by the command
    exiting 0: a flag that parsed and was then dropped on the floor would
    pass any weaker test while leaving the operator exactly as stuck."""
    _register_active(monkeypatch)
    jar = tmp_path / "burpsuite_community.jar"
    jar.write_bytes(b"")
    seen = {}

    @contextlib.contextmanager
    def fake(eng, *, instance, jar=None, workdir=None, seed=None):
        seen["jar"] = jar
        yield SimpleNamespace(operator_port=1, crawler_port=2, epoch=1,
                              bridge=object(), workdir=None, proc=None)

    monkeypatch.setattr(cli.session_mod, "session", fake)
    result = CliRunner().invoke(cli.main, [
        "scan", "--root", str(engagement_with_surface),
        "--burp-jar", str(jar)])
    assert result.exit_code == 0, result.output
    assert seen["jar"] == jar


def test_scan_and_capture_spell_the_jar_flag_the_same_way():
    """Two commands launching the same Burp for the same reason must not ask
    for it two ways -- an operator who learnt `--burp-jar` on `capture start`
    should not have to learn a second spelling, and a help text that drifted
    would document two different defaults for one `find_burp_jar`."""
    def option(command, name):
        return next(p for p in command.params if p.name == name)

    scan_jar = option(cli.scan, "burp_jar")
    capture_jar = option(cli.capture_start, "burp_jar")
    assert scan_jar.opts == capture_jar.opts
    assert scan_jar.help == capture_jar.help


# --- Task 8 fix round 1, F12/F2: `hx report` had no test at all, and F2 is ---
# --- what that gap already cost -----------------------------------------

def test_report_writes_a_file_and_says_where(engagement_with_surface):
    result = CliRunner().invoke(cli.main,
                                ["report", "--root", str(engagement_with_surface)])
    assert result.exit_code == 0, result.output
    target = engagement_with_surface / "exports" / "acme-2026-09.md"
    assert target.exists()
    assert str(target) in result.output


def test_report_default_export_is_never_looser_than_0o600(engagement_with_surface):
    """§3, unconditional. F2: `write_text` then `chmod` used to leave the
    file at `0o644` for the window between them; there is no window left to
    measure from the outside once the file exists, so this pins the mode
    the file ends at -- the live end-to-end half of F2's fix, the write-time
    window itself is what `_write_export_secure`'s O_EXCL-at-final-mode
    shape (`cli.py`) exists to close."""
    CliRunner().invoke(cli.main,
                       ["report", "--root", str(engagement_with_surface)])
    target = engagement_with_surface / "exports" / "acme-2026-09.md"
    assert oct(target.stat().st_mode & 0o777) == "0o600"


def test_report_out_creates_new_directories_at_0o700_not_the_umask(engagement_with_surface, tmp_path):
    """F2's exact measured repro: `--out <somewhere>/nested/report.md`, where
    neither `nested` directory exists yet. The old
    `target.parent.mkdir(parents=True, exist_ok=True)` created both at the
    ambient umask (`755` under `022`, measured in the review) -- including
    when the path was inside the engagement root, which §3 governs
    unconditionally. `secure_mkdir` must leave every directory it creates at
    `0o700`, never looser, with no window.

    R3 (fix round 2): the umask is set explicitly here, LOOSE (`022`), and
    restored after. Without this the test's separating power depended on
    whatever umask the developer's or CI's shell happened to have: under a
    restrictive ambient umask (`077`), the OLD buggy `mkdir(parents=True)`
    creates directories at `0o777 & ~0o077 == 0o700` too -- the same result
    the fix produces -- so the mutation this test exists to catch would pass
    vacuously there. A guard whose discriminating power depends on the
    environment it happens to run in is one that will quietly stop testing.
    """
    old_umask = os.umask(0o022)
    try:
        target = tmp_path / "handoff" / "client" / "acme.md"
        result = CliRunner().invoke(cli.main, [
            "report", "--root", str(engagement_with_surface), "--out", str(target),
        ])
    finally:
        os.umask(old_umask)
    assert result.exit_code == 0, result.output
    assert target.exists()
    assert oct(target.stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "handoff").stat().st_mode & 0o777) == "0o700"
    assert oct((tmp_path / "handoff" / "client").stat().st_mode & 0o777) == "0o700"


def test_report_redacts_a_credential_reaching_the_export(engagement_with_surface):
    """F1/F12: the export-side redaction the review found missing, exercised
    through the real CLI command rather than `report.render` directly --
    F2's own defect was found exactly this way, by driving the command
    end-to-end rather than trusting the unit-level render tests alone. The
    finding is hand-inserted rather than written through `records.py`'s own
    writers, the same way `records.record_exchange`/`record_denial` already
    redact at write time and would mask the gap this checks for."""
    eng = eng_mod.open_(engagement_with_surface)
    try:
        eng.db.execute(
            "INSERT INTO finding(id, engagement_id, dedupe_key, title,"
            " severity, confidence, created_by, status, scope_level)"
            " VALUES('f-1', ?, 'k1',"
            " 'Token leak: https://admin:hunter2@app.acme.com/x?access_token=SECRETTOKEN',"
            " 'Medium', 'Firm', 'check', 'new', 'surface')",
            (eng.id,))
    finally:
        eng.db.close()
    result = CliRunner().invoke(cli.main,
                                ["report", "--root", str(engagement_with_surface)])
    assert result.exit_code == 0, result.output
    target = engagement_with_surface / "exports" / "acme-2026-09.md"
    text = target.read_text(encoding="utf-8")
    assert "SECRETTOKEN" not in text
    assert "hunter2" not in text
    assert "Token leak" in text


def test_scan_tells_the_operator_how_many_canaries_it_sent(
        engagement_with_surface, monkeypatch):
    """F5 OF FIX ROUND A. Section 6: the canary "is counted in `requests_sent`
    for the run, because it is a request `hx` put on the client's system".
    `ScanSummary.canary_requests` counted it faithfully and was read by
    nothing -- not `check_run.requests_sent` (no row owns it), not the `run`
    table (no request column), not `report._limits` (no request tally at
    all). A number that satisfies a spec sentence and reaches nobody
    satisfies nothing.

    THE WHOLE PATH, not a stubbed summary: the config declares an identity
    and names it as `scan_identity`, the credential comes out of the
    environment, and the two canaries that bracket the run are the ones the
    line counts.
    """
    from tests.test_scan_probes import USER, _SessionBridge

    monkeypatch.setenv("HX_ID_USER", "session=abc")
    eng = eng_mod.open_(engagement_with_surface)
    try:
        eng.config = dataclasses.replace(
            eng.config, identities={USER.id: USER}, scan_identity=USER.id,
            scope_include=["https://app.acme.com/*"])
        eng_mod.record_scope_version(
            eng, author="test", reason="declare an identity for this scan")
    finally:
        eng.db.close()

    _stub_session(monkeypatch, bridge=_SessionBridge())
    result = CliRunner().invoke(
        cli.main, ["scan", "--root", str(engagement_with_surface)])

    assert result.exit_code == 0, result.output
    assert "canaries  2" in result.output, (
        "the run's own traffic reaches no reader: " + result.output)


def test_a_scan_with_no_identity_prints_no_canary_line(
        engagement_with_surface, monkeypatch):
    """THE OTHER HALF. An anonymous run sends no canary, and `canaries  0` on
    every scan is a line an operator learns to skip past -- which is how the
    one that matters gets missed."""
    _stub_session(monkeypatch)
    result = CliRunner().invoke(
        cli.main, ["scan", "--root", str(engagement_with_surface)])

    assert result.exit_code == 0, result.output
    assert "canaries" not in result.output, result.output


def _declare_identity(root, ident, monkeypatch, *, value="session=abc",
                      export=True):
    """Give the engagement at `root` one identity and scan under it.

    The scope becomes a URL PREFIX rather than whatever the fixture carries.
    It stopped being the identity's `origins` in branch fix A -- the
    credential is bounded to the one host the canary proves -- but scope is
    still what decides whether a probe may be sent at all.
    `record_scope_version` is called because `engagement.open_` refuses a
    store whose config and newest scope version have diverged, and every
    `hx scan` below opens the store for itself.

    `export=False` DECLARES THE IDENTITY WITHOUT SETTING ITS VARIABLE, for
    the operator mistake that is ordinary rather than the session that dies
    mid-run: a static identity whose `HX_ID_USER` was simply never
    exported."""
    if export:
        monkeypatch.setenv("HX_ID_USER", value)
    eng = eng_mod.open_(root)
    try:
        eng.config = dataclasses.replace(
            eng.config, identities={ident.id: ident}, scan_identity=ident.id,
            scope_include=["https://app.acme.com/*"])
        eng_mod.record_scope_version(
            eng, author="test", reason="declare an identity for this scan")
    finally:
        eng.db.close()


def test_a_dead_session_is_reported_as_a_result_and_not_a_traceback(
        engagement_with_surface, monkeypatch):
    """HAZARD ONE OF TASK 8. `scan.run` halts on a session it cannot prove --
    spec s7's instruction, and s6's reason: a dead session produces a run of
    "not vulnerable" answers indistinguishable from a clean application --
    and `hx scan` caught only `SessionError`, so the one outcome this plan
    exists to make visible reached an operator as a stack trace.

    THE MESSAGE NAMES WHICH OF SECTION 6'S FOUR OUTCOMES IT WAS. `user` is
    static, so the table gives it no refresh: the operator is told that
    rather than left to wonder whether their (nonexistent) refresh command
    ran. It also says the canary was ANSWERED rather than refused, which is
    the difference between re-authenticating and fixing a scope that bounds
    the credential to no host at all.
    """
    from tests.test_scan_probes import USER, _SessionBridge

    _declare_identity(engagement_with_surface, USER, monkeypatch)
    # A session that never proves, at any generation the run can reach.
    _stub_session(monkeypatch, bridge=_SessionBridge(live_at_generation=99))
    result = CliRunner().invoke(
        cli.main, ["scan", "--root", str(engagement_with_surface)])

    assert result.exit_code != 0, result.output
    assert result.exception is None or isinstance(result.exception,
                                                  SystemExit), (
        "the halt escaped as an exception: an operator reads a traceback "
        f"instead of a result -- {result.exception!r}")
    assert "could not be proved live before the first probe" in result.output
    assert "no refresh command to try" in result.output, (
        "the message does not say which of section 6's outcomes happened, so "
        f"an operator cannot tell where to look: {result.output}")
    assert "`fails, static`" in result.output
    assert "not with the signature this identity is declared to prove itself "\
        "by" in result.output, (
            "a canary that was ANSWERED reads like one that was refused: "
            + result.output)


def test_an_unexported_identity_variable_is_reported_as_a_result_and_not_a_traceback(
        engagement_with_surface, monkeypatch):
    """FINDING 3 OF THE TASK 8 REVIEW. `hx scan` caught `IdentityDead` (the
    session that WAS opened and then died or never proved live) but not
    `hx.identity.IdentityError`, which is what `_resolve_scan_identity`
    raises when a declared identity's variable was simply never exported --
    no session is ever opened for this case, so `IdentityDead` was never
    going to catch it. Forgetting an `export` is the ordinary mistake, one
    exception class over from the rarer one commit a88388d fixed, and until
    now it still reached the operator as a traceback.
    """
    from tests.test_scan_probes import USER, _SessionBridge

    _declare_identity(engagement_with_surface, USER, monkeypatch, export=False)
    _stub_session(monkeypatch, bridge=_SessionBridge())
    result = CliRunner().invoke(
        cli.main, ["scan", "--root", str(engagement_with_surface)])

    assert result.exit_code != 0, result.output
    assert result.exception is None or isinstance(result.exception,
                                                  SystemExit), (
        "the missing export escaped as an exception: an operator reads a "
        f"traceback instead of a result -- {result.exception!r}")
    assert "HX_ID_USER" in result.output, (
        "the operator is not told which variable to export: " + result.output)
    assert "not set" in result.output
    assert "Traceback" not in result.output

    eng = eng_mod.open_(engagement_with_surface)
    try:
        row = eng.db.execute(
            "SELECT status, identity, identity_state, stop_reason FROM run"
            " WHERE kind='scan'").fetchone()
    finally:
        eng.db.close()
    assert row[0] == "error", tuple(row)
    assert "IdentityError" in row[3]
    assert "HX_ID_USER" in row[3]


def test_an_unwritable_credential_is_reported_as_a_result_and_not_a_traceback(
        engagement_with_surface, monkeypatch):
    """F5 OF THE WHOLE-BRANCH REVIEW, FIRST ARM. `BridgeServer.
    register_identity`'s own docstring tells its caller it "has two exception
    types to handle, not one" -- `BridgeError` and `codec.FrameError` --
    `_IdentityBracket.start` deliberately wraps neither, and `hx scan` caught
    neither. So a credential with an internal newline, which is what a token
    pasted out of a file looks like, reached the operator as a traceback with
    the sentence `codec._refuse_unwritable` had already written for them at
    the bottom of it.

    THE VALUE IS NOWHERE IN THE OUTPUT, and that is the same rule the refusal
    itself follows: `_refuse_unwritable` never quotes the character or the
    text it came from, because a `FrameError`'s message is logged by whatever
    catches it. `X-Smuggled` is the half of this credential that would show up
    if it did.
    """
    from tests.test_scan_probes import USER, _SessionBridge

    class _BuildsTheBody(_SessionBridge):
        """`_SessionBridge`, plus the one statement that raises this.

        The real `BridgeServer.register_identity` builds the frame body with
        `codec.identity_body(...)` BEFORE it writes anything to the socket,
        and that call is where an unwritable credential is refused. Every
        other double in this suite skips it, so the whole chain from
        `HX_ID_USER` to the operator's terminal had no test that could see
        this exception at all -- which is how it went unhandled.
        """

        def register_identity(self, resolved, *, origins):
            cli.codec_mod.identity_body(resolved.id, resolved.generation,
                                        resolved.header, resolved.value,
                                        origins)
            super().register_identity(resolved, origins=origins)

    _declare_identity(engagement_with_surface, USER, monkeypatch,
                      value="session=abc\r\nX-Smuggled: yes")
    _stub_session(monkeypatch, bridge=_BuildsTheBody())
    result = CliRunner().invoke(
        cli.main, ["scan", "--root", str(engagement_with_surface)])

    assert result.exit_code != 0, result.output
    assert result.exception is None or isinstance(result.exception,
                                                  SystemExit), (
        "the refusal escaped as an exception: an operator reads a traceback "
        f"instead of a result -- {result.exception!r}")
    assert "carriage return or line feed" in result.output, result.output
    assert "Traceback" not in result.output
    assert "X-Smuggled" not in result.output, (
        "the credential reached the operator's terminal: " + result.output)

    eng = eng_mod.open_(engagement_with_surface)
    try:
        row = eng.db.execute(
            "SELECT status, stop_reason FROM run WHERE kind='scan'").fetchone()
    finally:
        eng.db.close()
    assert row[0] == "error", tuple(row)
    assert "X-Smuggled" not in row[1], (
        "the credential reached the run row, which the report renders")


def test_a_peer_that_refuses_the_identity_frame_is_a_result_too(
        engagement_with_surface, monkeypatch):
    """F5'S OTHER ARM, AND WHY ONE HANDLER COVERS BOTH. `register_identity`
    raises `BridgeError` when the peer refuses the frame or is gone -- a
    `bad_identity`, a `stale_generation`, a socket that closed. From the
    operator's side that is the same outcome as the arm above: the identity
    could not be registered, so no probe was issued under it and the run
    stopped. What differs is the message, and it is the message that is kept
    intact.
    """
    from tests.test_scan_probes import USER, _SessionBridge

    class _RefusingBridge(_SessionBridge):
        def register_identity(self, resolved, *, origins):
            raise cli.bridge_mod.BridgeError(
                "peer refused identity: bad_identity: generation must be >= 1",
                error_class="bad_identity")

    _declare_identity(engagement_with_surface, USER, monkeypatch)
    _stub_session(monkeypatch, bridge=_RefusingBridge())
    result = CliRunner().invoke(
        cli.main, ["scan", "--root", str(engagement_with_surface)])

    assert result.exit_code != 0, result.output
    assert result.exception is None or isinstance(result.exception,
                                                  SystemExit), (
        "the peer's refusal escaped as an exception -- "
        f"{result.exception!r}")
    assert "bad_identity" in result.output, (
        "the peer's own refusal class was lost: " + result.output)
    assert "Traceback" not in result.output


def test_a_halted_scan_leaves_the_run_row_error_and_dead(
        engagement_with_surface, monkeypatch):
    """The halt is a RESULT, so it has to be recorded as one. `report.
    _provenance` names the run among those that did not finish and
    `report._identity` says prominently that the session died -- both read
    the run row, and neither can say anything if the halt left it
    `running`."""
    from tests.test_scan_probes import USER, _SessionBridge

    _declare_identity(engagement_with_surface, USER, monkeypatch)
    _stub_session(monkeypatch, bridge=_SessionBridge(live_at_generation=99))
    CliRunner().invoke(cli.main, ["scan", "--root",
                                  str(engagement_with_surface)])

    eng = eng_mod.open_(engagement_with_surface)
    try:
        row = eng.db.execute(
            "SELECT status, identity, identity_state, stop_reason FROM run"
            " WHERE kind='scan'").fetchone()
        assert (row[0], row[1], row[2]) == ("error", "user", "dead"), tuple(row)
        assert "IdentityDead" in row[3]
        rendered = report.render(eng.db, engagement_id=eng.id,
                                 config=eng.config, blobs=eng.blobs)
    finally:
        eng.db.close()
    assert ("**1 run(s) stopped because the session being tested under "
            "stopped being valid.**") in rendered
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_cli.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.cli'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/hx/cli.py
"""Command line entry points.

Creating an engagement and inspecting one are human acts, so they live here
rather than in the agent-facing tool layer.
"""
from __future__ import annotations

import contextlib
import dataclasses
import os
import re
import signal
import sqlite3
import time
import uuid
from pathlib import Path

import click

from hx import config as config_mod
from hx import engagement as eng_mod
from hx import halt as halt_mod
from hx import identity as identity_mod
from hx import report as report_mod
from hx import run as run_mod
from hx import scan as scan_mod
from hx import session as session_mod
from hx import triage as triage_mod
from hx.bridge import codec as codec_mod
from hx.bridge import server as bridge_mod
from hx.checks import registry
from hx.crawl import frontier as frontier_mod
from hx.crawl import run as crawl_run_mod
from hx.store import db as db_mod
from hx.store.paths import secure_mkdir

_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def default_root() -> Path:
    env = os.environ.get("HX_HOME")
    if env:
        return Path(env)
    return Path.home() / "hx" / "engagements"


def _open_engagement(path: Path) -> eng_mod.Engagement:
    """`eng_mod.open_`, with every failure turned into a `ClickException`
    instead of a traceback. Shared by `info` and both `capture` subcommands,
    which all open an existing engagement the same way `info` always has.
    """
    try:
        return eng_mod.open_(path)
    except eng_mod.EngagementError as exc:
        raise click.ClickException(str(exc)) from exc
    except config_mod.ConfigError as exc:
        raise click.ClickException(f"invalid config at {path}: {exc}") from exc
    except sqlite3.Error as exc:
        raise click.ClickException(f"cannot read the database at {path}: {exc}") from exc
    except OSError as exc:
        raise click.ClickException(f"cannot access the engagement at {path}: {exc}") from exc


@click.group()
def main() -> None:
    """hx — agent-driven web application security assessment."""


@main.command()
@click.argument("name")
@click.option("--client", required=True, help="Client name, as it appears in the report.")
@click.option(
    "--scope",
    "scope",
    multiple=True,
    required=True,
    help="In-scope URL pattern. Repeatable. At least one is required.",
)
@click.option("--exclude", multiple=True, help="Excluded URL pattern. Repeatable.")
@click.option(
    "--profile",
    type=click.Choice(config_mod.VALID_PROFILES),
    default="production",
    show_default=True,
)
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--author", default=lambda: os.environ.get("USER", "unknown"))
def new(name, client, scope, exclude, profile, root, author) -> None:
    """Create a new engagement."""
    for field, value in (("NAME", name), ("--client", client)):
        if not value.strip():
            raise click.ClickException(f"{field} must not be empty")
    # The same refusal one field along, and it has to be HERE rather than only
    # in config.load(): this command builds a Config directly and dumps() it,
    # so the load-time guard does not run until the engagement already exists.
    # `hx new --exclude ""` wrote `exclude: ['']` to config.yaml and to the
    # scope_version row, and the operator found out on the next open. The
    # extension still fails closed on an empty pattern -- it is not a bypass --
    # but the guard exists so that the operator learns at `hx new`.
    for option, values in (("scope.include", scope), ("scope.exclude", exclude)):
        try:
            config_mod.check_entries(option, list(values))
        except config_mod.ConfigError as exc:
            raise click.ClickException(str(exc)) from exc
    # NAME becomes a path segment under the engagements root (`base / name`).
    # Without this check, "." makes the engagements root ITSELF an
    # engagement (so `rm -rf` of it destroys every client), ".." or
    # "../escaped" walk outside the root, and an absolute NAME like
    # "/tmp/anywhere" makes pathlib's `/` operator discard `base` entirely
    # -- `--root` silently ignored. User-controlled NAME also reaches
    # `shutil.rmtree` on create()'s failure path, so this has to hold before
    # any directory is touched.
    if not _NAME_RE.fullmatch(name) or name in (".", ".."):
        raise click.ClickException(
            "NAME must be 1-64 characters of letters, digits, dot, underscore "
            "or hyphen, and must start with a letter or digit"
        )
    base = root or default_root()
    cfg = config_mod.Config(
        name=name,
        client=client,
        safety_profile=profile,
        scope_include=list(scope),
        scope_exclude=list(exclude),
    )
    try:
        eng = eng_mod.create(base / name, cfg, author=author)
    except eng_mod.EngagementError as exc:
        raise click.ClickException(str(exc)) from exc
    except config_mod.ConfigError as exc:
        raise click.ClickException(f"invalid config for {base / name}: {exc}") from exc
    except sqlite3.Error as exc:
        raise click.ClickException(f"cannot create the database at {base / name}: {exc}") from exc
    except OSError as exc:
        raise click.ClickException(f"cannot create the engagement at {base / name}: {exc}") from exc

    click.echo(f"created engagement {name} ({eng.id})")
    click.echo(f"  root    {eng.root}")
    click.echo(f"  profile {cfg.safety_profile}")
    click.echo(f"  scope   {', '.join(cfg.scope_include)}")


def _group_counts(conn, table: str, column: str) -> str:
    """`SELECT column, COUNT(*) FROM table GROUP BY column`, rendered as
    `value=n  value=n`. The database holds exactly one engagement (I5), so
    no WHERE clause is needed -- the same assumption `info`'s row counts
    below have always made."""
    rows = conn.execute(
        f"SELECT {column} AS k, COUNT(*) AS n FROM {table} GROUP BY {column}"
    ).fetchall()
    return "  ".join(f"{r['k']}={r['n']}" for r in rows) or "none"


@main.command()
@click.option("--root", type=click.Path(path_type=Path), default=None)
def info(root) -> None:
    """Show an engagement's configuration and current counts."""
    path = root or default_root()
    eng = _open_engagement(path)
    try:
        # First, so a run whose harness died reads `error` rather than a
        # `running` that has not been true for a while -- otherwise the
        # first thing an operator sees after a crash is a run that claims
        # to still be live.
        run_mod.reap_stale(eng.db)

        counts = {
            t: eng.db.execute(f"SELECT COUNT(*) AS n FROM {t}").fetchone()["n"]
            for t in ("run", "surface", "exchange", "finding", "check_run")
        }
        runs_by_status = _group_counts(eng.db, "run", "status")
        surfaces_by_kind = _group_counts(eng.db, "surface", "kind")
        exchanges_by_outcome = _group_counts(eng.db, "exchange", "outcome")
        denials_by_kind = _group_counts(eng.db, "denial", "kind")
        dropped_total = eng.db.execute(
            "SELECT COALESCE(SUM(dropped_total), 0) AS n FROM run"
        ).fetchone()["n"]
    except sqlite3.Error as exc:
        raise click.ClickException(f"cannot read the database at {path}: {exc}") from exc

    click.echo(f"engagement {eng.config.name} ({eng.id})")
    click.echo(f"  client   {eng.config.client}")
    click.echo(f"  profile  {eng.config.safety_profile}")
    click.echo(f"  scope    {', '.join(eng.config.scope_include)}")
    if eng.config.scope_exclude:
        click.echo(f"  exclude  {', '.join(eng.config.scope_exclude)}")
    click.echo(f"  root     {eng.root}")
    click.echo("  counts   " + "  ".join(f"{k}={v}" for k, v in counts.items()))
    click.echo(f"  runs      {runs_by_status}")
    click.echo(f"  surfaces  {surfaces_by_kind}")
    click.echo(f"  exchanges {exchanges_by_outcome}")
    click.echo(f"  denials   {denials_by_kind}")
    # THE HALT, and only when there is one -- the same rule the drop warning
    # below follows, so a line that appears means something. S4 makes the
    # sentinel a path an operator can take from a shell with no harness
    # running, which means an operator can also arrive at a halted engagement
    # they did not halt themselves. `info` is where they look first, and until
    # this line nothing in the CLI could tell them issuance was stopped.
    #
    # Read through OperatorHalt rather than by testing for the file, so this
    # sees a halt recorded in the store as well as one on disk -- `halted` is
    # a union, and the two can disagree when a harness died between the two
    # writes.
    halt_state = _operator_halt(eng)
    if halt_state.halted:
        click.echo(f"  HALTED    {halt_state.reason}")
        click.echo(f"            issuance is stopped; `hx resume` lifts it "
                   f"and records who did ({halt_state.sentinel_path})")
    # S5: a run with drops has coverage numbers that are a FLOOR, not a
    # complete count -- only said out loud when it is true, so it stays
    # meaningful when it fires.
    if dropped_total > 0:
        click.echo(
            f"  WARNING   {dropped_total} dropped: the surface and exchange "
            "counts above are a FLOOR, not the whole picture -- the "
            "extension could not hand over every exchange."
        )


@main.group()
def capture() -> None:
    """Start or stop traffic capture for an engagement."""


# How often `capture start` asks whether the session it is holding open is
# still a session. A second is far below anything a human notices and far
# above anything the check costs: `Popen.poll()` is a non-blocking waitpid and
# the bridge state is an attribute read.
_HEALTH_POLL_S = 1.0


def _block_until_interrupt(live) -> str | None:
    """Hold the session open until the operator interrupts -- or Burp dies.

    Returns None when the wait ended the way it usually does (Ctrl-C, which
    arrives as a KeyboardInterrupt out of `time.sleep`), or the reason the
    session stopped being one.

    NOT `signal.pause()` ANY MORE, and that is S8's "Burp dies mid-session"
    path. Paused, a command whose Burp had died blocked forever: the browser
    got connection-refused, nothing was printed, and the run row stayed
    `status='running'` until the operator gave up and pressed Ctrl-C, which
    then closed the run as though they had ended it on purpose. Nothing polled
    `proc.poll()` or re-read the bridge state, so the only witness was the
    consultant noticing their proxy had stopped answering.

    Separate so a test can drive the command without a real signal.
    """
    while True:
        why = live.gone()
        if why is not None:
            return why
        time.sleep(_HEALTH_POLL_S)


@contextlib.contextmanager
def _sigterm_ends_the_session():
    """SIGTERM tears Burp down instead of orphaning it.

    S7: "A Burp process is never orphaned." `capture_start` covered Ctrl-C and
    exceptions, and SIGTERM -- a `kill`, a terminal closing, a service manager
    stopping the unit -- killed the command where it stood, leaving a 900 MB
    JVM and a bridge socket behind. The next run then got the (good) stale
    socket refusal naming the path to remove.

    Raised as KeyboardInterrupt deliberately: a SIGTERM is somebody stopping
    this command, which is what Ctrl-C is, and giving the two paths one
    meaning keeps one teardown and one `stop_reason` rather than two that have
    to agree. The previous handler is restored on the way out, and a
    non-main-thread caller (where `signal.signal` raises) simply does not get
    the handler -- an inability to install one must not stop the session.
    """
    def handler(signum, frame):
        raise KeyboardInterrupt

    try:
        previous = signal.signal(signal.SIGTERM, handler)
    except ValueError:
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


@capture.command("start")
@click.option(
    "--kind",
    type=click.Choice(sorted(run_mod.RUN_KINDS)),
    default="browse",
    show_default=True,
    help="Run kind. The vocabulary is derived from the schema, not restated.",
)
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option(
    "--burp-jar",
    type=click.Path(path_type=Path),
    default=None,
    help="Which Burp jar to launch against. Default: $HX_BURP_JAR, then the "
         "one jar found in $HX_BURP_LAB -- two jars there is an error, never "
         "a guess, because the report records the version under test.",
)
@click.option(
    "--max-requests",
    type=click.IntRange(min=1),
    default=None,
    help="Per-run request budget, authorised on the extension's first "
         "configure. Default: the engagement's own config.yaml (2000 if "
         "unset) -- this flag overrides that number for this run only, it "
         "does not rewrite config.yaml.",
)
def capture_start(kind, root, burp_jar, max_requests) -> None:
    """Launch Burp, open the live run of KIND, and hold the session open
    until interrupted.

    THE SESSION OPENS BEFORE THE RUN. A run row opened in front of a
    session that then fails to start is a run that never captured
    anything, and `hx report` would go on to render it as a real one.

    This is `run.current_run`, not `run.open_run`: typing `start` twice
    resumes the one live run of that kind rather than opening a second one.
    """
    path = root or default_root()
    eng = _open_engagement(path)
    if max_requests is not None:
        # A per-invocation OVERRIDE, not a rewrite: `eng.config` is replaced
        # in memory so `session.config_body` picks it up, and `config.yaml`
        # on disk is untouched -- the flag says what THIS run authorises,
        # the file stays the record of what the operator wrote down.
        eng.config = dataclasses.replace(eng.config, max_requests=max_requests)
    try:
        with _sigterm_ends_the_session(), \
                session_mod.session(eng, instance="capture", jar=burp_jar) as live:
            click.echo(f"operator proxy listening on 127.0.0.1:{live.operator_port}")
            try:
                run_id = run_mod.current_run(
                    eng.db, engagement_id=eng.id, kind=kind,
                    safety_profile=eng.config.safety_profile)
            except sqlite3.Error as exc:
                raise click.ClickException(
                    f"cannot write to the database at {path}: {exc}") from exc
            died = None
            try:
                # The echo lives IN the try, not between it and current_run's:
                # `hx capture start | head` closes the pipe once `head` has
                # what it wants, Python does not restore SIGPIPE, and this
                # echo is the first write after the run opens -- outside the
                # try that BrokenPipeError would escape past the finally
                # below, leaving the run open and never closed.
                click.echo(f"{kind} run {run_id} is live")
                died = _block_until_interrupt(live)
            finally:
                # Runs even when the block above ends in a KeyboardInterrupt
                # or a BrokenPipeError: a run left `status='running'` after
                # the operator's Burp is gone would read as a live capture
                # forever.
                #
                # A DEAD BURP IS NOT A COMPLETED RUN. `run.py`'s own rule --
                # "a run whose harness DIED resolves to `error`, never to
                # `completed`, because a report generated from a session that
                # stopped halfway and claims to be complete is the worst
                # output this project could produce" -- and the reason
                # `stop_reason` carries the message rather than the word
                # "operator": S5 renders it, and an operator reading the
                # report should find out there that Burp went away.
                try:
                    run_mod.close_run(
                        eng.db, run_id=run_id,
                        status="error" if died else "completed",
                        stop_reason=died or "operator")
                except sqlite3.Error as exc:
                    raise click.ClickException(
                        f"cannot write to the database at {path}: {exc}") from exc
            if died:
                # Raised INSIDE the `with`, so `session()`'s teardown still
                # runs: a Burp that died is a Burp whose bridge socket and
                # accept thread are still this process's to clean up. S8 asks
                # for a distinct message and a non-zero exit; ClickException
                # is both, and it is not a SessionError, so the handler below
                # does not re-wrap it.
                raise click.ClickException(died)
    except session_mod.SessionError as exc:
        raise click.ClickException(str(exc)) from exc


@capture.command("stop")
@click.option(
    "--kind",
    type=click.Choice(sorted(run_mod.RUN_KINDS)),
    default=None,
    help="Close only runs of this kind. Default: every live run.",
)
@click.option("--root", type=click.Path(path_type=Path), default=None)
def capture_stop(kind, root) -> None:
    """Close every live run of the engagement (`--kind` narrows it to one).

    An operator typing `stop` means every kind currently recording, because
    a crawl can run while a human browses and those are two runs -- "stop
    capturing" means both. Closed with status='completed',
    stop_reason='operator': an operator ending a run on purpose is neither
    an `error` nor `aborted`, which mean the harness or the auto-halt ended
    it instead.
    """
    path = root or default_root()
    eng = _open_engagement(path)
    try:
        query = "SELECT id FROM run WHERE status='running'"
        params: list[str] = []
        if kind is not None:
            query += " AND kind=?"
            params.append(kind)
        rows = eng.db.execute(query, params).fetchall()
        if not rows:
            suffix = f" of kind {kind}" if kind else ""
            click.echo(f"no live runs{suffix} to stop")
            return
        with db_mod.transaction(eng.db):
            for row in rows:
                run_mod.close_run(eng.db, run_id=row["id"], status="completed",
                                  stop_reason="operator")
    except sqlite3.Error as exc:
        raise click.ClickException(f"cannot write to the database at {path}: {exc}") from exc
    click.echo(f"stopped {len(rows)} run(s)")


def _operator_halt(eng: eng_mod.Engagement) -> halt_mod.OperatorHalt:
    """The SAME `OperatorHalt` the extension polls, built the same way.

    S4 gives the kill switch three independent paths and the whole argument is
    "any one works when the others are wedged". Two of the three were
    unreachable by a human before these commands existed: `BridgeServer.halt()`
    and `resume()` are correct and durable and had no CLI and no production
    driver, and the STOP button in the Burp suite tab is unbuilt and stated as
    such. So of the three, only "create the sentinel file from a shell" was
    something an operator could actually do -- and the path §4 argues for is
    the redundancy, not any one of them.

    NOT A SECOND PATH. An operator halt is durable, and durable means the row
    AND the file: `OperatorHalt.halt` writes the sentinel FIRST so a failure to
    explain cannot become a failure to stop, and `resume` writes the row first
    so a failure to record cannot lift a halt silently. A CLI that touched the
    file itself would have neither ordering and no audit trail. The path is
    `<engagement>/HALTED`, which is what `burp_fixture.launch_burp` passes as
    `-Dhx.halt_sentinel` -- so the file this writes is the file the extension
    polls, and there is no third spelling of it anywhere.

    NO FRAME IS SENT, and that is not an omission. The bridge lives in the
    harness process, not this one; the sentinel is the path that works when
    the bridge does not, and the extension polls it directly. A harness that
    IS running re-reads the same file: `OperatorHalt.halted` is a union of the
    armed flag and a stat(), so a halt written from another process is seen by
    `BridgeServer.send` on its next call and re-asserted after any hello.
    """
    try:
        return halt_mod.OperatorHalt(eng.root, eng.db)
    except halt_mod.HaltError as exc:
        raise click.ClickException(str(exc)) from exc
    except sqlite3.Error as exc:
        raise click.ClickException(
            f"cannot read the halt state at {eng.root}: {exc}") from exc


@main.command()
@click.option("--reason", default=None,
              help="Why issuance is being stopped. Recorded in the audit trail "
                   "and written into the sentinel file for whoever finds it.")
@click.option("--root", type=click.Path(path_type=Path), default=None)
def halt(reason, root) -> None:
    """Stop issuance for an engagement, durably.

    `--reason` is OPTIONAL on purpose. This is a kill switch, and the moment
    it is used is the moment something is going wrong on a client's
    production system; a required argument is friction in front of a stop.
    The default says who stopped it and how, which is the part a later reader
    cannot reconstruct.
    """
    path = root or default_root()
    eng = _open_engagement(path)
    oh = _operator_halt(eng)
    was = oh.reason if oh.halted else None
    text = reason or f"halted from the command line by {os.environ.get('USER', 'unknown')}"
    try:
        oh.halt(text)
    except (sqlite3.Error, OSError) as exc:
        # The sentinel is written before the row, so a failure here may mean
        # the halt IS in force and only its audit line is missing. Say which
        # rather than leaving the operator to guess, because the guess that
        # matters is "did it stop".
        raise click.ClickException(
            f"halt failed after {'writing' if oh.sentinel_path.exists() else 'failing to write'} "
            f"{oh.sentinel_path}: {exc}") from exc
    if was is not None:
        click.echo(f"already halted: {was}")
    click.echo(f"issuance halted: {text}")
    click.echo(f"  sentinel {oh.sentinel_path}")
    click.echo("  the extension polls that file and refuses every send while "
               "it exists; `hx resume` is how to lift it -- deleting the file "
               "by hand also lifts it for the extension, and records nothing")


@main.command()
@click.option("--root", type=click.Path(path_type=Path), default=None)
def resume(root) -> None:
    """Re-arm issuance, and record that it was re-armed.

    A `configure` re-authorises SCOPE and never issuance, and a reconnect
    re-asserts the halt rather than clearing it -- so nothing in the bridge
    lifts a halt by accident, which is what makes refusing to run this on an
    un-halted engagement safe rather than pedantic.

    IT IS NOT THE ONLY WAY BACK, and an earlier version of this docstring said
    it was. `rm <engagement>/HALTED` also lifts the halt AS FAR AS THE
    EXTENSION IS CONCERNED -- the extension polls the file and nothing else,
    which is precisely what S4 asks of it ("an operator can create it from a
    shell when the socket is dead"), and a mechanism that can be created by
    hand can be removed by hand. What that loses is the record: no
    `agent_action` row says who lifted it, and a harness process that had
    already read `_armed` from the store goes on refusing sends of its own
    while the extension issues. This command is the one that leaves both
    sides agreeing and leaves a row behind.
    """
    path = root or default_root()
    eng = _open_engagement(path)
    oh = _operator_halt(eng)
    if not oh.halted:
        # Nothing is written. `resume()` would append a resume row for a stop
        # that never happened, and an audit trail whose entries do not
        # correspond to events is worse than a short one.
        click.echo("not halted; nothing to resume")
        return
    was = oh.reason
    try:
        oh.resume()
    except (sqlite3.Error, OSError) as exc:
        # The row goes first, so a failure here leaves the sentinel in place
        # and the halt STANDING -- which is the direction S4 asks for, and is
        # worth saying out loud rather than reporting a bare error.
        raise click.ClickException(
            f"resume failed and the halt still stands ({oh.sentinel_path}): {exc}"
        ) from exc
    click.echo(f"issuance resumed; the halt was: {was}")


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


@main.command()
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--max-seconds", type=int, default=None,
              help="Stop after this long. Remaining checks are recorded as "
                   "skipped, never left absent.")
@click.option(
    "--max-requests",
    type=click.IntRange(min=1),
    default=None,
    help="Per-run request budget an active check's session is authorised "
         "against. Default: the engagement's own config.yaml (2000 if "
         "unset) -- this flag overrides that number for this run only, it "
         "does not rewrite config.yaml.",
)
# F6 of the whole-branch review. THE SAME OPTION `capture start` HAS, spelt
# the same way and with the same help text, because it answers the same
# question about the same launch. `hx scan` opens a Burp on every default
# run now (`active_safe` is on in `DEFAULT_CHECKS` and five active checks
# ship), and without this an operator with two jars in `$HX_BURP_LAB` and no
# `$HX_BURP_JAR` could not scan at all: `find_burp_jar` refuses to guess,
# deliberately -- the report records the version under test -- and this was
# the only command with no way to answer it.
@click.option(
    "--burp-jar",
    type=click.Path(path_type=Path),
    default=None,
    help="Which Burp jar to launch against. Default: $HX_BURP_JAR, then the "
         "one jar found in $HX_BURP_LAB -- two jars there is an error, never "
         "a guess, because the report records the version under test.",
)
def scan(root, max_seconds, max_requests, burp_jar) -> None:
    """Run the enabled check corpus over everything captured so far."""
    path = root or default_root()
    eng = _open_engagement(path)
    if max_requests is not None:
        # Same override as `capture start`'s -- see its comment. `scan.run`
        # takes `eng.config` as-is, and the active-check session opened
        # below hands the same object to `session.config_body`, so this
        # single replacement is what authorises the extension for THIS
        # invocation. It must stay ahead of both.
        eng.config = dataclasses.replace(eng.config, max_requests=max_requests)
    try:
        surfaces = eng.db.execute(
            "SELECT COUNT(*) FROM surface WHERE engagement_id=?",
            (eng.id,)).fetchone()[0]
        if surfaces == 0:
            # NOT an error, and not silence either. Nothing captured is a
            # different fact from nothing found, and an operator who forgot
            # to browse must not read `0 findings` as a clean bill.
            click.echo("no surfaces captured yet -- browse the target "
                       "through the proxy first, then scan")
            return

        # THE SESSION IS OPENED HERE, AND ONLY WHEN SOMETHING WILL SEND.
        # `scan.run` takes a bridge and never builds one: it has no
        # engagement root, no jar and no business owning a JVM whose
        # lifetime is a local variable's. This command has all three.
        #
        # ONLY WHEN SOMETHING WILL SEND, because a passive scan that paid
        # Burp's ~10 s startup to send nothing would be a cost with no answer
        # attached. THE COMMON `hx scan` IS NOT THAT SCAN ANY MORE, and the
        # sentence here used to say it was: "the corpus this build ships is
        # still all passive, so the common `hx scan` stays entirely offline"
        # survived Tasks 7 through 13 and both of Task 13's fix rounds, by
        # which time five `active_safe` checks were registered and
        # `config.DEFAULT_CHECKS` had `active_safe: True`. A default-
        # configured engagement opens a Burp on every scan; what stays
        # offline is a scan of an engagement whose config has switched the
        # active classes off, which is now the exception rather than the
        # rule. The guard below is unchanged -- it was always the right
        # guard, and only its justification was stale.
        #
        # TWO FILTERS, TWO DIFFERENT QUESTIONS, AND NEITHER IS RESTATED HERE.
        # `registry.enabled` is the one place "switched on for this
        # engagement" is decided, which also settles a class enabled with no
        # checks in it (the shipped `active_timing`) -- `enabled` returns
        # nothing for it, so it starts no Burp. `scan.needs_a_bridge` is the
        # one place "will the runner send for this check" is decided, and it
        # answers by asking which hook the runner would dispatch to.
        #
        # This second one was `c.klass != "passive"` until fix round 1 (LOW):
        # a class-string restatement of a rule the registry owns, of exactly
        # the kind `scan._runner_hook` refuses to make. A future non-passive
        # class whose `_HOOKS` entry never gets `probes` would have launched
        # a JVM here while `scan.run` called `on_surface` and sent nothing,
        # with no test anywhere pinning the disagreement.
        sending = tuple(c for c in registry.enabled(eng.config)
                        if scan_mod.needs_a_bridge(c))
        try:
            if sending:
                with session_mod.session(eng, instance="scan",
                                          jar=burp_jar) as live:
                    summary = scan_mod.run(
                        eng.db, engagement_id=eng.id, blobs=eng.blobs,
                        config=eng.config, max_seconds=max_seconds,
                        bridge=live.bridge)
            else:
                summary = scan_mod.run(
                    eng.db, engagement_id=eng.id, blobs=eng.blobs,
                    config=eng.config, max_seconds=max_seconds)
        except session_mod.SessionError as exc:
            # The message intact, as `capture start` does: every one of
            # them already names the fix (a stale socket to remove, an
            # unbuilt extension jar, a listener that came up off loopback),
            # and re-wording it here would put this command between the
            # operator and the sentence that tells them what to do.
            raise click.ClickException(str(exc)) from exc
        except scan_mod.IdentityDead as exc:
            # A DEAD SESSION IS A RESULT, NOT A CRASH -- and until Task 8 it
            # was a traceback. `scan.run` halts rather than scanning
            # anonymously (spec s7's instruction, and the identity design's
            # s6 gives the reason: a dead session produces a run of "not
            # vulnerable" answers that look exactly like a clean
            # application), and nothing here caught it, so the one outcome
            # this whole plan exists to make visible arrived at an operator
            # as a stack trace with the sentence at the bottom.
            #
            # THE MESSAGE INTACT, for the reason above it: it names which of
            # section 6's four outcomes happened (`_IdentityBracket._outcome`
            # -- `fails, static` and `fails after refresh` send an operator
            # to different places), whether the canary was REFUSED or
            # answered without the declared signature (`_unproved` -- a
            # refused canary means no credential they can mint will help),
            # and why halting was the right answer.
            #
            # NON-ZERO EXIT, like every other `ClickException`, and that is
            # the point rather than an accident: the run did not complete,
            # its `run` row reads `error`, and a shell that treated this as
            # success would let a scheduled scan report clean coverage for
            # an application it stopped testing at the first surface. The
            # run's own tallies are in that row's `stop_reason`
            # (`scan._halt_reason`) and reach a reader through `hx report`,
            # not through this line.
            raise click.ClickException(str(exc)) from exc
        except identity_mod.IdentityError as exc:
            # THE FAR COMMONER MISTAKE, ONE EXCEPTION CLASS OVER FROM
            # `IdentityDead` ABOVE. `_resolve_scan_identity` (`scan.py:986`)
            # reads a static identity's credential out of `os.environ` and
            # RAISES `IdentityError` when the declared variable was simply
            # never exported -- no session was ever opened, no canary was
            # ever sent, so `IdentityDead` (which is a session that WAS
            # proved and then died, or never provably lived) is the wrong
            # class for it and always was. Forgetting an `export` on a
            # terminal an operator just opened is ordinary; nothing here
            # caught it, so it reached them as a traceback with the message
            # `identity.resolve` already wrote for them at the bottom of it
            # -- the same defect commit a88388d fixed for the rarer case,
            # one exception class over.
            #
            # THE MESSAGE INTACT, for the same reason as above: `resolve`
            # already names the variable that is missing and refuses to
            # issue anonymously rather than silently testing the logged-out
            # view of an authenticated application, and re-wording it here
            # would put this command between the operator and the sentence
            # that tells them what to do. No credential value is in it --
            # `resolve` raises before it has one to leak.
            #
            # NON-ZERO EXIT, like every other `ClickException`: the run's
            # own row still closes `error` (`scan.run`'s `except
            # BaseException`, unconditionally), so nothing here masks a
            # scan that sent no probe or canary as one that succeeded.
            raise click.ClickException(str(exc)) from exc
        except (bridge_mod.BridgeError, codec_mod.FrameError) as exc:
            # THE TWO `register_identity` FLAGS FOR ITS CALLER, AND NEITHER
            # HAD ONE. F5 of the whole-branch review. That method's docstring
            # says in as many words that the caller "has two exception types
            # to handle, not one", `_IdentityBracket.start` deliberately
            # wraps neither -- correctly, since each says what actually
            # happened -- and this command caught neither. So a credential
            # with an internal newline or a smart quote pasted out of a file
            # reached the operator as a traceback, with the sentence
            # `codec._refuse_unwritable` had already written for them at the
            # bottom of it. The same defect commit a88388d fixed for
            # `IdentityDead` and 20b0a64 for `IdentityError`, two doors over.
            #
            # BOTH ARMS, ONE HANDLER, because from the operator's side they
            # are one outcome: the identity could not be registered, so no
            # probe was issued under it and the run stopped. The message is
            # what tells them which -- `FrameError` names the character class
            # and why such a value is refused rather than escaped, and
            # `BridgeError` names the peer's own refusal class.
            #
            # THE MESSAGE INTACT, and it holds no credential: every branch of
            # `_refuse_unwritable` refuses to quote the character or the text
            # it came from (spec section 5 -- the credential is logged on
            # neither side, and a caught `FrameError`'s message is logged by
            # whatever catches it), and `register_identity`'s `BridgeError`
            # quotes the peer's `class` and `detail`, which the extension
            # builds from the identity id and the host and never from the
            # value. A traceback would have leaked nothing either -- Python
            # prints source lines, not values -- so this is about the
            # operator's experience of an ordinary mistake, not about a leak.
            #
            # NOT NARROWER THAN `BridgeError`, deliberately. Every other
            # bridge failure a scan can suffer is already translated before
            # it gets here: `ProbeSender` turns one into a `ProbeRefused`
            # (`probe.py`'s `except BridgeError`), which the runner records
            # as an `inconclusive` row. What is left to arrive raw is the
            # identity registration, which is the one this handler is for.
            raise click.ClickException(str(exc)) from exc
        click.echo(f"surfaces  {summary.surfaces}")
        click.echo(f"checks    {summary.checks_run}")
        click.echo(f"findings  {summary.findings}")
        if summary.skipped:
            for reason, n in sorted(summary.by_reason.items()):
                click.echo(f"skipped   {n} ({reason})")
        # A DIFFERENT LINE FROM `skipped`, and F11's reason for existing: a
        # skipped row is one the runner never ran, a refused probe is one it
        # ran and the extension or the bridge said no to. `budget_exhausted`
        # here is the operator's warning that everything after some point in
        # the corpus was reported `inconclusive` -- the same sentence the
        # run row's `stop_reason` now carries.
        for reason, n in sorted(summary.refused.items()):
            click.echo(f"refused   {n} ({reason})")
        # THE CANARIES ARE HX'S OWN TRAFFIC AND AN OPERATOR IS TOLD ABOUT
        # THEM -- F5 of the task-7 fix round A review. Section 6 says the
        # canary "is counted in `requests_sent` for the run, because it is a
        # request `hx` put on the client's system", and
        # `ScanSummary.canary_requests` counted it faithfully and was READ BY
        # NOTHING: `check_run.requests_sent` excludes it (no check asked for
        # it, so no row owns it), the `run` table has no request column, and
        # `report._limits` renders no request tally at all. A number that
        # satisfies a spec sentence and reaches nobody satisfies nothing.
        #
        # THIS IS NOT THE WHOLE OF WHAT SECTION 6 ASKS and the difference is
        # worth naming rather than papering over: the section says
        # `requests_sent` FOR THE RUN, and this build has no such column to
        # add it to. What it can have today is the operator being told, at
        # the same terminal that already gets `skipped` and `refused`, that
        # a run put N requests of its own on a client's system. The client's
        # own copy of that fact belongs in section 10's identity section,
        # which the plan gives to Task 8, derived from the run.
        #
        # ONLY WHEN THERE WERE ANY. An anonymous run sends no canary, and
        # `canaries  0` on every scan is a line an operator learns to skip.
        if summary.canary_requests:
            click.echo(f"canaries  {summary.canary_requests}")

        # A class the operator enabled that this build ships nothing for.
        # Without this line, `active_timing: true` plus no rows reads as
        # "ran, found nothing".
        for klass, on in sorted(eng.config.checks.items()):
            if on and not any(c.klass == klass for c in registry.CHECKS):
                click.echo(f"note      {klass} is enabled but this build "
                           f"ships no checks in it")
    finally:
        eng.db.close()


@main.command("crawl")
@click.option("--target", "targets", multiple=True, required=True,
              help="Seed URL to crawl from. Repeatable -- one call may "
                   "start from several origins at once.")
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--max-pages", type=click.IntRange(min=1), default=200,
              show_default=True,
              help="Page budget. Exhausting it truncates the crawl and the "
                   "printed summary names which budget stopped it.")
@click.option("--max-seconds", type=click.IntRange(min=1), default=600,
              show_default=True, help="Wall-clock budget for the crawl.")
@click.option(
    "--max-requests",
    type=click.IntRange(min=1),
    default=5000,
    show_default=True,
    help="Per-run request budget, authorised on the extension's first "
         "configure -- the same flag `capture start` and `scan` carry, "
         "spelt the same way.",
)
@click.option(
    "--burp-jar",
    type=click.Path(path_type=Path),
    default=None,
    help="Which Burp jar to launch against. Default: $HX_BURP_JAR, then the "
         "one jar found in $HX_BURP_LAB -- two jars there is an error, never "
         "a guess, because the report records the version under test.",
)
def crawl(targets, root, max_pages, max_seconds, max_requests,
          burp_jar) -> None:
    """Drive a browser over TARGETS through a fresh Burp session.

    Long crawls belong here, outside an agent's session: `crawl.run` is the
    same crawler, bounded, for a mid-session sweep. THE SESSION OPENS
    BEFORE THE RUN, as `capture start`'s does and for the same reason -- a
    run row opened in front of a session that then fails to start is a run
    that never captured anything.
    """
    path = root or default_root()
    eng = _open_engagement(path)
    # Unconditional, unlike `capture start`'s and `scan`'s override: this
    # flag always carries a value (5000 by default, never None), so the
    # session this launches is always authorised for exactly the budget the
    # crawl itself is bounded by -- a crawl asking the browser for more
    # requests than the extension was configured to allow would just start
    # collecting policy denials once it ran past the smaller number.
    eng.config = dataclasses.replace(eng.config, max_requests=max_requests)
    try:
        try:
            with session_mod.session(eng, instance="crawl",
                                      jar=burp_jar) as live:
                run_id = run_mod.open_run(
                    eng.db, engagement_id=eng.id, kind="crawl",
                    safety_profile=eng.config.safety_profile)
                died = None
                # BOUND BEFORE THE `try`, because the `finally` below reads it:
                # on a crash `summary` would otherwise be unbound and the
                # cleanup that exists to close the run row would itself raise
                # NameError, leaving the row open -- the exact failure it is
                # there to prevent.
                summary = None
                try:
                    summary = crawl_run_mod.crawl(
                        seeds=targets,
                        # THE CRAWLER PORT, NEVER THE OPERATOR ONE -- see
                        # `hx.tools.live`'s module docstring for why the two
                        # are not interchangeable.
                        proxy_port=live.crawler_port,
                        budget=frontier_mod.Budget(
                            max_pages=max_pages, max_seconds=max_seconds,
                            max_requests=max_requests))
                except BaseException as exc:
                    # A DEAD BROWSER IS NOT A COMPLETED RUN, exactly as a
                    # dead Burp is not for `capture start`: the run row must
                    # not read `completed` for a crawl that stopped because
                    # its instrument broke rather than because the frontier
                    # ran dry. `BaseException`, deliberately, not `Exception`
                    # -- a Ctrl-C here is a `KeyboardInterrupt`, and closing
                    # the run row on that path matters exactly as much as
                    # closing it on a crawler crash: an operator who
                    # interrupts a long crawl must not leave the run row
                    # open forever either.
                    died = f"{type(exc).__name__}: {exc}"
                finally:
                    # A TRUNCATED CRAWL IS A `completed` RUN, and without the
                    # `truncated_by` half of this line it is indistinguishable
                    # from an exhaustive one: `stop_reason` was `died`, which
                    # is None on every success, so a crawl stopped at page 1
                    # of 500 recorded a clean finish and said nothing. S8
                    # designates this CLI for LONG crawls -- the ones that
                    # actually reach a budget -- so the surface most likely to
                    # truncate was the one least able to say so.
                    #
                    # `crawl.run`'s path needs no equivalent: it returns
                    # `truncated_by` to the agent, which owns its own run
                    # lifecycle and passes the reason to `run.finish(note=...)`
                    # -- that lands in this same column. The asymmetry is who
                    # closes the run, not what gets recorded.
                    reason = died
                    if reason is None and summary is not None:
                        reason = (f"truncated: {summary.truncated_by}"
                                  if summary.truncated_by else None)
                    run_mod.close_run(
                        eng.db, run_id=run_id,
                        status="error" if died else "completed",
                        stop_reason=reason)
                if died:
                    # A CLEAN MESSAGE, NOT A TRACEBACK -- `capture_start`'s
                    # own rule for a died-mid-session Burp, applied here to
                    # a died-mid-crawl browser. The run row above already
                    # carries the raw exception in `stop_reason`; what an
                    # operator running a security tool against a client's
                    # application sees at the terminal is this one line, not
                    # a stack trace out of `hx.crawl.run.crawl`.
                    raise click.ClickException(died)
        except session_mod.SessionError as exc:
            raise click.ClickException(str(exc)) from exc

        click.echo(f"pages     {summary.pages}")
        click.echo(f"rendered  {summary.rendered}")
        click.echo(f"degraded  {summary.degraded}")
        click.echo(f"failed    {summary.failed}")
        click.echo(f"capped    {summary.capped}")
        click.echo(f"requests  {summary.requests}")
        if summary.dropped_hosts:
            click.echo(f"dropped   {', '.join(summary.dropped_hosts)}")
            # F2: `dropped_hosts` is built from SEED origins, not scope
            # (`hx.crawl.page.classify`'s docstring has the full statement).
            # On an engagement whose scope covers a second origin that was
            # never seeded, a target-side failure there reads as a policy
            # drop here. The denial rows are the JVM's own record of what it
            # actually refused and remain authoritative -- confirm a host
            # here was truly dropped by policy against those, not this line
            # alone, before pasting it into `render_allow`.
            click.echo("          confirm against this engagement's denial "
                       "rows, which remain authoritative, before pasting "
                       "any of the above into render_allow")
        # TRUNCATION IS PRINTED EITHER WAY. A truncated crawl that stopped on
        # a budget and reported only its counts would read as a complete
        # crawl of a small application -- S12's failure with the numbers
        # intact -- and the silent case (no line at all) is exactly that
        # shape, so both outcomes get an explicit line.
        if summary.truncated_by:
            click.echo(f"truncated {summary.truncated_by}")
        else:
            click.echo("truncated no -- the frontier ran dry before any "
                       "budget did")
        # F1: SPEC §9 -- the crawl summary AND the report's Limits section
        # must both disclose these four things in as many words. §8 makes
        # this CLI the surface for long crawls, and the operator who ran one
        # from a terminal is the one most likely to over-read a clean-looking
        # result; `report.py`'s Limits bullet already says this, and
        # `crawl.run`'s `as_tool_result` already says it to the agent
        # (`NOT_DONE`, `hx.crawl.run`) -- this reuses that exact wording
        # rather than inventing a fifth phrasing of the same four facts.
        for line in crawl_run_mod.NOT_DONE:
            click.echo(f"not done  {line}")
    finally:
        eng.db.close()


def _write_export_secure(path: Path, text: str) -> None:
    """Atomically write the report at 0o600, never briefly looser.

    Fix round 1, F2: `target.parent.mkdir(parents=True, exist_ok=True)`
    followed by `write_text` then `chmod` created directories at the ambient
    umask (`755` under `umask 022`, measured, including directories nested
    inside the engagement root when `--out` named one) and left the file
    itself at `0o644` for the window between the write and the chmod, on
    every invocation. §3 is unconditional -- "engagement directories `0o700`,
    files `0o600`, never looser" -- and a client report earns no less care
    than `config.yaml` or the halt sentinel.

    Same shape as `engagement._write_config_secure` and
    `halt.OperatorHalt._write_sentinel`, for the same reasons: `O_EXCL` at
    the final mode so the file never exists world-readable even for an
    instant, and a rename so a reader never sees a partial write. Not a
    shared import of either -- this codebase's own precedent
    (`halt._write_sentinel`'s docstring: "Same shape as
    `engagement._write_config_secure`, for the same reasons") is to
    duplicate this exact shape per module with a cross-reference, not to
    import a leading-underscore name across module boundaries.
    """
    path = Path(path)
    tmp = path.parent / f".{uuid.uuid4().hex}.{path.name}"
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        fh = os.fdopen(fd, "w", encoding="utf-8")
    except BaseException:
        os.close(fd)
        Path(tmp).unlink(missing_ok=True)
        raise
    try:
        with fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


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
        secure_mkdir(target.parent)   # S3: 0o700, never looser, no window
        _write_export_secure(target, text)   # S3: 0o600, never looser
        click.echo(f"wrote {target}")
    finally:
        eng.db.close()


@main.command("tool")
@click.argument("name", required=False)
@click.option("--json", "args_json", default=None,
              help="Arguments as a JSON object.")
@click.option("--why", default=None,
              help="Why you are doing this. Required by state-changing tools; "
                   "written to agent_action.")
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--list", "list_only", is_flag=True,
              help="List every tool and exit.")
def tool(name, args_json, why, root, list_only) -> None:
    """Call one agent tool and print its envelope as JSON."""
    from hx.tools.adapters import cli as tool_cli

    if list_only or not name:
        click.echo(tool_cli.render_listing())
        return
    eng = _open_engagement(root or default_root())
    text, status = tool_cli.run_tool(eng, name, args_json, why)
    click.echo(text)
    if status:
        raise SystemExit(status)


@main.command("mcp")
@click.option("--root", type=click.Path(path_type=Path), default=None)
def mcp(root) -> None:
    """Serve the tool layer over MCP on stdio.

    THE ADAPTER THAT CAN HOLD A BURP. `hx tool` is one process per call and
    `hx.session.session()` tears Burp down on every exit, so egress tools
    there answer `no_host`. This command is one process for the whole
    conversation: `run.start` brings a session up and `run.finish` -- or any
    exit from this command -- takes it down.

    NOTHING BUT JSON-RPC MAY REACH STDOUT while this runs.
    """
    from hx.tools.adapters import mcp as mcp_adapter

    eng = _open_engagement(root or default_root())
    # S7 AGAIN, AND THIS COMMAND NEEDS IT MOST. `serve` holds the session on an
    # `ExitStack`, which unwinds on a return, an exception, or the agent closing
    # the pipe -- but NOT on SIGTERM, whose default disposition ends the process
    # without running a single `__exit__`. `hx mcp` is the one command built to
    # hold a Burp open for a whole conversation, so it is the one most likely to
    # be running under a service manager or a container and the one most likely
    # to be stopped by `docker stop` or a redeploy: exactly the signal that
    # leaves a 900 MB JVM and a bridge socket behind.
    #
    # `run.reap_stale` does not save this. It marks run rows stale; it never
    # kills a process, so nothing downstream recovers the orphan.
    #
    # `capture_start` has carried this wrapper since S7 was written. Its absence
    # here made `mcp.py`'s own docstring -- "ANY exit from `serve` ... unwinds
    # [the stack]" -- false for the single exit that matters in production.
    with _sigterm_ends_the_session():
        mcp_adapter.serve(eng)


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

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_cli.py -v`
Expected: PASS, 5 passed

- [ ] **Step 5: Run the whole suite and the real CLI**

Run: `.venv/bin/pytest -v`
Expected: PASS, 30 passed

```bash
HX_HOME=/tmp/hx-smoke .venv/bin/hx new smoke --client "Smoke Test" --scope 'http://127.0.0.1:3000/*'
HX_HOME=/tmp/hx-smoke .venv/bin/hx info --root /tmp/hx-smoke/smoke
ls -la /tmp/hx-smoke/smoke        # expect drwx------ and hx.db, blobs, config.yaml, exports
rm -rf /tmp/hx-smoke
```

- [ ] **Step 6: Commit**

```bash
git add src/hx/cli.py tests/test_cli.py
git commit -m "feat(cli): hx new and hx info"
```

---

## Self-review

**Spec coverage.** §3 engagement directory layout → Task 4. §5 all 14 tables, pragmas, single-writer discipline, `dedupe_key` uniqueness, blob atomicity, agent-cannot-confirm → Tasks 1, 2, 4. §5 append-only `scope_version` → Task 4. §13 "engagement.create is not agent-facing" → Task 5 (CLI only).

**Deliberately out of this plan**, covered by later plans: scope *matching* (Plan 2, authoritative implementation lives in the Java extension); `path_template` normalisation (Plan 5, alongside the crawler that produces surfaces); the single-writer queue (Plan 2, when concurrent writers first exist — this plan uses one connection and has no concurrency to serialise yet).

**Known gap accepted for now:** `Config.scope_include` is a mutable list on a frozen dataclass, which `test_scope_versions_are_append_only` relies on via `.append()`. That is intentional for v1 ergonomics; if it causes aliasing bugs later, switch to `dataclasses.replace` with a fresh list.

---

## Execution handoff

Plan complete. Two execution options:

1. **Subagent-Driven (recommended)** — a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — execute tasks in this session with checkpoints for review.
