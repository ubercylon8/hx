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
