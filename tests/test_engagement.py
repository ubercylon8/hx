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
