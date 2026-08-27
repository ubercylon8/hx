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
