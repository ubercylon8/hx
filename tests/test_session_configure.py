"""The configure body, and the scope hash it is authorised against.

Two things live here because they are one authorisation: `config_body`
builds the wire body `hx capture start` will hand to `bridge.configure()`,
and `stored_scope_sha256` supplies the hash that authorises it -- READ from
`scope_version`, never recomputed from today's `config.yaml`. See
`session.stored_scope_sha256`'s own docstring for why recomputing is the
failure this module exists to design out.
"""
import sqlite3
from types import SimpleNamespace

import pytest

from hx import config as config_mod
from hx import engagement as engagement_mod
from hx import session
from hx.bridge import codec
from hx.store import db as db_mod
from hx.store.paths import secure_mkdir


# --- fixtures ----------------------------------------------------------


@pytest.fixture
def a_config() -> config_mod.Config:
    """A `Config` with every relevant field distinct from every other, so a
    test that reads the wrong attribute into the wrong key fails loudly
    instead of by coincidence passing."""
    return config_mod.Config(
        name="acme-2026-09",
        client="Acme Corp",
        scope_include=["https://app.acme.com/*"],
        scope_exclude=["https://app.acme.com/logout*"],
        dangerous_paths=["*/purge*"],
        render_allow=["https://app.acme.com/*"],
        rate_limit_rps=7,
        max_concurrency=3,
    )


@pytest.fixture
def engagement(tmp_path):
    """A real, on-disk engagement -- the way `hx.engagement.create()` makes
    one, the same call `tests/test_engagement.py` drives directly. Its
    initial `scope_version` row is written atomically by `create()` itself,
    which is exactly the row `stored_scope_sha256` must read back.

    Yields `(conn, eng)`: `conn` is `eng.db`, pulled out separately so the
    tests read the way `tests/test_halt.py`'s `engagement` fixture does.
    """
    cfg = config_mod.Config(
        name="acme-2026-09", client="Acme Corp",
        scope_include=["https://app.acme.com/*"],
    )
    eng = engagement_mod.create(tmp_path / "acme", cfg, author="jimx")
    yield eng.db, eng
    eng.db.close()


@pytest.fixture
def empty_engagement(tmp_path):
    """An engagement row with NO `scope_version` row at all -- the state
    `stored_scope_sha256` must refuse rather than silently pass through.

    Built by hand from the store primitives, the way `tests/test_halt.py`'s
    `test_a_store_with_no_engagement_row_is_refused` builds its own empty
    store: `hx.engagement.create()` always writes the engagement row and its
    scope_version row in one transaction, so there is no way to reach this
    state through that API. The gap is the point.
    """
    root = tmp_path / "empty"
    secure_mkdir(root)
    conn = db_mod.connect(root / "hx.db")
    db_mod.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e-1','Example','Example Ltd',1,'active')")
    yield conn, SimpleNamespace(id="e-1", root=root)
    conn.close()


# --- config_body ---------------------------------------------------------


def test_the_body_uses_only_keys_the_codec_permits(a_config):
    assert set(session.config_body(a_config)) <= codec.CONFIG_KEYS


def test_every_config_field_reaches_its_key(a_config):
    body = session.config_body(a_config)
    assert body["scope.include"] == a_config.scope_include
    assert body["scope.exclude"] == a_config.scope_exclude
    assert body["dangerous.path"] == a_config.dangerous_paths
    assert body["render.allow"] == a_config.render_allow
    assert body["limit.rate_rps"] == [str(a_config.rate_limit_rps)]
    assert body["limit.concurrency"] == [str(a_config.max_concurrency)]
    assert body["method.allow"] == ["GET", "HEAD", "OPTIONS"]


def test_the_budget_key_is_absent(a_config):
    # Java's Limits.arm() falls back to its documented default of 2000, and
    # S4 says the budget never binds the operator's browser. The plan that
    # spends it is the plan that bounds it.
    assert "limit.max_requests" not in session.config_body(a_config)


# --- stored_scope_sha256 --------------------------------------------------


def test_the_scope_hash_is_read_from_the_store(engagement):
    conn, eng = engagement
    stored = conn.execute(
        "SELECT sha256 FROM scope_version WHERE engagement_id=?"
        " ORDER BY effective_from_us DESC LIMIT 1", (eng.id,)).fetchone()[0]
    assert session.stored_scope_sha256(conn, eng.id) == stored


def test_a_hand_edited_config_does_not_change_the_authorised_hash(engagement):
    """The failure this rule prevents.

    If the session recomputed the hash from today's config, the report would
    render one hash as the authorised scope while the extension had been
    authorised against another -- and nothing would notice.
    """
    conn, eng = engagement
    before = session.stored_scope_sha256(conn, eng.id)
    (eng.root / "config.yaml").write_text(
        (eng.root / "config.yaml").read_text() + "\n# a comment\n")
    assert session.stored_scope_sha256(conn, eng.id) == before


def test_an_engagement_with_no_scope_version_is_an_error(empty_engagement):
    conn, eng = empty_engagement
    with pytest.raises(session.SessionError):
        session.stored_scope_sha256(conn, eng.id)
