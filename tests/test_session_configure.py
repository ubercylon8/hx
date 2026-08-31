"""The configure body, and the scope hash it is authorised against.

Two things live here because they are one authorisation: `config_body`
builds the wire body `hx capture start` will hand to `bridge.configure()`,
and `stored_scope_sha256` supplies the hash that authorises it -- READ from
`scope_version`, never recomputed from today's `config.yaml`. See
`session.stored_scope_sha256`'s own docstring for why recomputing is the
failure this module exists to design out.
"""
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
    assert body["limit.max_requests"] == [str(a_config.max_requests)]
    assert body["method.allow"] == ["GET", "HEAD", "OPTIONS"]


def test_the_budget_reaches_the_authorisation(a_config):
    # Task 6: `hx.checks.probe.ProbeSender` is the send seam that spends the
    # budget, so the plan that starts spending it is the plan that bounds it
    # -- the key is no longer absent, and its value is `Config.max_requests`.
    assert session.config_body(a_config)["limit.max_requests"] == [str(a_config.max_requests)]


def test_the_budget_key_is_one_the_codec_permits(a_config):
    assert set(session.config_body(a_config)) <= codec.CONFIG_KEYS


# --- stored_scope_sha256 --------------------------------------------------


def test_the_scope_hash_is_read_from_the_store(engagement):
    conn, eng = engagement
    stored = conn.execute(
        "SELECT sha256 FROM scope_version WHERE engagement_id=?"
        " ORDER BY effective_from_us DESC LIMIT 1", (eng.id,)).fetchone()[0]
    assert session.stored_scope_sha256(conn, eng.id) == stored


def test_a_hand_edited_comment_does_not_change_the_authorised_hash(engagement):
    """A weak but cheap check: appending a comment does not disturb the
    stored hash.

    NOT the test that distinguishes "read from the store" from "recompute
    from the file". `config.dumps()` is a canonical re-serialisation of the
    parsed `Config` -- comments and key order are discarded before hashing,
    so `dumps(load(x + "# comment"))` is byte-identical to `dumps(load(x))`.
    A recompute-from-config implementation passes this test too. See
    `test_a_field_edit_that_survives_reserialisation_does_not_change_the_authorised_hash`
    below for the one that actually pins "read, never recompute".
    """
    conn, eng = engagement
    before = session.stored_scope_sha256(conn, eng.id)
    (eng.root / "config.yaml").write_text(
        (eng.root / "config.yaml").read_text() + "\n# a comment\n")
    assert session.stored_scope_sha256(conn, eng.id) == before


def test_a_field_edit_that_survives_reserialisation_does_not_change_the_authorised_hash(engagement):
    """The failure this rule prevents, proved by a mutation that a
    recompute-from-config implementation cannot pass.

    Unlike a bare comment, `rate_limit_rps: 5 -> 10` SURVIVES a
    `config.load()` / `config.dumps()` round trip: it is a real field on the
    parsed `Config`, not discarded formatting. A `stored_scope_sha256` that
    read `engagement.config_path`, reloaded it and re-hashed `dumps(cfg)`
    would return a DIFFERENT hash here -- only a read of the stored
    `scope_version` row returns the same one recorded at `create()` time.

    If the session recomputed the hash from today's config, the report would
    render one hash as the authorised scope while the extension had been
    authorised against another -- and nothing would notice.
    """
    conn, eng = engagement
    before = session.stored_scope_sha256(conn, eng.id)
    config_path = eng.root / "config.yaml"
    text = config_path.read_text()
    assert "rate_limit_rps: 5" in text, "fixture assumption changed; edit no longer applies"
    config_path.write_text(text.replace("rate_limit_rps: 5", "rate_limit_rps: 10"))
    assert session.stored_scope_sha256(conn, eng.id) == before


def test_an_engagement_with_no_scope_version_is_an_error(empty_engagement):
    conn, eng = empty_engagement
    with pytest.raises(session.SessionError):
        session.stored_scope_sha256(conn, eng.id)


def test_the_latest_of_several_scope_versions_wins(engagement):
    """`ORDER BY effective_from_us DESC LIMIT 1`, actually exercised against
    more than one row.

    Follows `tests/test_engagement.py`'s use of
    `engagement.record_scope_version()` to append a second, real row rather
    than hand-inserting one -- that call is the only legitimate way a second
    `scope_version` row comes to exist, and it stamps `effective_from_us`
    itself (`engagement.now_us()`), so a hand-inserted row would either have
    to guess that or risk two rows landing at the same microsecond.
    """
    conn, eng = engagement
    first = session.stored_scope_sha256(conn, eng.id)

    eng.config.scope_include.append("https://api.acme.com/*")
    engagement_mod.record_scope_version(
        eng, author="jimx", reason="client added API host")

    second = session.stored_scope_sha256(conn, eng.id)
    assert second != first
    assert session.stored_scope_sha256(conn, eng.id) == second


def test_two_rows_at_one_microsecond_break_the_tie_the_report_breaks_it(engagement):
    """The one fact S5 says must not become two facts.

    `stored_scope_sha256` authorises the extension; `report._scope_of_record`
    renders the boundary a contract dispute is read off. They ordered
    differently -- `effective_from_us DESC LIMIT 1` here against
    `effective_from_us, rowid` there, taking the last -- so two rows stamped
    in the same microsecond let the extension be authorised against one row
    while the deliverable rendered the other, with nothing to notice.

    `record_scope_version` stamps `engagement.now_us()`, so the tie is
    possible rather than impossible; it is hand-inserted here because
    producing it through that API means winning a race with the clock. The
    assertion is not a hard-coded row: it is the report's OWN ordering,
    executed here, so the two cannot drift apart again without this failing.
    """
    conn, eng = engagement
    when, = conn.execute(
        "SELECT effective_from_us FROM scope_version WHERE engagement_id=?",
        (eng.id,)).fetchone()
    conn.execute(
        "INSERT INTO scope_version(id, engagement_id, yaml, sha256,"
        " effective_from_us, author, reason)"
        " VALUES('sv-same-us', ?, 'name: later', 'b' * 64, ?, 'jimx',"
        " 'stamped in the same microsecond as the row before it')",
        (eng.id, when))

    boundary_of_record = conn.execute(
        "SELECT sv.sha256 FROM scope_version sv WHERE sv.engagement_id=?"
        " ORDER BY sv.effective_from_us, sv.rowid", (eng.id,)).fetchall()[-1][0]

    assert session.stored_scope_sha256(conn, eng.id) == boundary_of_record, (
        "the extension would be authorised against one scope_version row "
        "while the report renders another as the boundary of record")
