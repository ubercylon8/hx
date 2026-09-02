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


def test_a_deleted_config_file_scans_as_a_problem(tmp_path):
    """A store can have a perfectly good `hx.db` and no `config.yaml` --
    deleted, moved, or never written back after an edit. The overview
    handler needs a config to render at all, so a directory missing one is
    exactly as unusable as a directory whose schema is wrong, and the index
    must say so rather than link to a screen that cannot render.
    """
    _make(tmp_path, "alpha")
    (tmp_path / "alpha" / "config.yaml").unlink()

    entry = registry_mod.scan(tmp_path)[0]

    assert entry.problem is not None
    assert "config.yaml" in entry.problem
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
