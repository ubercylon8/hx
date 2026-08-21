import sqlite3
from pathlib import Path

import pytest

from hx.store import db


def test_connect_applies_required_pragmas(tmp_path: Path):
    conn = db.connect(tmp_path / "hx.db")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000


def test_init_schema_creates_every_table(tmp_path: Path):
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    present = {
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert set(db.TABLES) <= present


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
    """A dangling first_seen_run reference is rejected by FK constraint."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e1','acme','Acme',1,'active')"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
            " path_template, first_seen_run)"
            " VALUES('s1','e1','GET','https','app.acme.com',443,'/api/users','NO_SUCH_RUN')"
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
