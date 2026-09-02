"""Fixtures shared across the whole tree.

This file is imported during COLLECTION for every test under `tests/`,
`tests/integration/` included -- so it stays fixtures only, with no import
that has a side effect. `tests/integration/conftest.py`'s own docstring
warns about the same collection-time cost for that directory; a root
conftest pays it for the other 700-odd tests too.
"""
from __future__ import annotations

import sqlite3

import pytest

from hx import config as config_mod
from hx.store import db as db_mod


@pytest.fixture
def engagement_conn():
    """An in-memory store, schema applied, with the pragmas and rows every
    test in this tree that writes a `finding` needs to be real.

    F3 of the task-5 review: this fixture used to open with `foreign_keys`
    at SQLite's own default (OFF) while `db_mod.connect` -- what every other
    unit test in the tree goes through -- turns it ON, and `db.py`'s own
    docstring says every connection must apply the same pragmas. Under ON,
    the very inserts these tests make reference run ids (`r-1`, `r-2`) and
    exchange ids (`x-1`, `x-2`, `x-9`) that named no real row, so they raised
    `IntegrityError: FOREIGN KEY constraint failed` -- which is exactly the
    gap between this fixture and production the finding was about, not a
    reason to leave the pragma off. Fixed by turning it ON and giving those
    ids real rows to reference, rather than by re-arguing the exemption.

    `sqlite3.connect(":memory:", isolation_level=None)` directly, not
    `db_mod.connect` -- that one takes a real path, pre-creates the file at
    0600 and does the WAL/pragma dance a throwaway in-memory connection has
    no file to apply it to. `isolation_level=None` is set explicitly to match
    `db_mod.connect`'s own autocommit connection: `record_evidence` wraps its
    writes in `db.transaction`, which issues an explicit `BEGIN`, and that
    raises against a connection already sitting inside sqlite3's own implicit
    transaction. The row factory is left at the sqlite3 default (a plain
    tuple), not `sqlite3.Row`: `tests/test_records_findings.py` compares a
    fetched row against a literal tuple, which `sqlite3.Row` does not equal.
    """
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.execute("PRAGMA foreign_keys=ON")
    db_mod.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e-1','T','T',1,'active')")
    for run_id in ("r-1", "r-2"):
        conn.execute(
            "INSERT INTO run(id, engagement_id, kind, safety_profile,"
            " started_us, status) VALUES(?,'e-1','manual','staging',1,"
            "'completed')", (run_id,))
    for exchange_id in ("x-1", "x-2", "x-9"):
        conn.execute(
            "INSERT INTO exchange(id, run_id, via, outcome, sent_us, method,"
            " url) VALUES(?,'r-1','send','ok',1,'GET','https://app.test/')",
            (exchange_id,))
    yield conn
    conn.close()


def _scan_env(*, passive: bool):
    """An in-memory engagement with one surface and one exchange against it,
    and a `Config` whose `checks.passive` is on or off.

    Separate from `engagement_conn`: that fixture seeds `run` and `exchange`
    rows for the finding/evidence unit tests and has no `surface` row at all
    -- `hx.scan.run` queries `surface` first and would iterate zero of them
    against it. `foreign_keys=ON` for the same reason `engagement_conn`
    turned it on: it is what `db_mod.connect` actually does, and a scan_env
    that let a dangling reference through would test a laxer database than
    hx ever opens for real.
    """
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.execute("PRAGMA foreign_keys=ON")
    db_mod.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e-1','T','T',1,'active')")
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES('s-1','e-1','GET','https','app.test',443,'/','proxy',1)")
    conn.execute(
        "INSERT INTO exchange(id, run_id, surface_id, via, outcome, sent_us,"
        " method, url) VALUES('x-1', NULL, 's-1', 'proxy', 'ok', 1, 'GET',"
        " 'https://app.test/')")
    checks = dict(config_mod.DEFAULT_CHECKS)
    checks["passive"] = passive
    cfg = config_mod.Config(
        name="T", client="T", scope_include=["*.test"], checks=checks)
    return {"conn": conn, "engagement_id": "e-1", "blobs": None, "config": cfg}


@pytest.fixture
def scan_env():
    env = _scan_env(passive=True)
    yield env
    env["conn"].close()


@pytest.fixture
def scan_env_disabled():
    env = _scan_env(passive=False)
    yield env
    env["conn"].close()


@pytest.fixture
def engagement(tmp_path):
    """A throwaway engagement on disk: config, database and blob store.

    Returns `hx.engagement.Engagement`, NOT the `(root, conn)` tuple
    `tests/test_halt.py` defines under this same name. A local fixture wins
    over conftest, so that file keeps its own; the two shapes are worth
    knowing about before reaching for either.

    `staging` rather than `production` because nothing here sends a request
    and the stricter profile would only make a future egress test harder to
    write than it needs to be.
    """
    from hx import config as config_mod
    from hx import engagement as eng_mod

    cfg = config_mod.Config(name="t", client="T", safety_profile="staging",
                            scope_include=["https://app.test/*"])
    eng = eng_mod.create(tmp_path / "e", cfg, author="test")
    yield eng
    eng.db.close()


@pytest.fixture
def tool_ctx(engagement):
    """A ToolContext over a throwaway engagement, with no run and no session.

    `run_id` is None because a fresh process has no open run, and `session` is
    None because nothing in Plan A needs egress -- which is exactly the state
    `needs_egress` tools are refused against.

    `engagement.db`'s `row_factory` is reset to the sqlite3 default (a plain
    tuple) before use. `db_mod.connect` sets it to `sqlite3.Row`, but
    `test_tools_dispatch.py` compares a `fetchall()` result to a literal list
    of tuples, and every Task 6-11 handler in this plan indexes a fetched row
    positionally (`row[0]`, `row[1]`, ...), never by column name. `Row` and a
    plain tuple both support positional indexing, so nothing downstream needs
    `Row`; only this fixture's own equality-against-a-tuple tests do, and
    `hx.engagement.create` has finished its own row reads by the time this
    fixture receives `eng`, so resetting it here is safe.
    """
    from hx import halt as halt_mod
    from hx.tools import dispatch

    engagement.db.row_factory = None
    return dispatch.ToolContext(
        engagement=engagement, conn=engagement.db, blobs=engagement.blobs,
        config=engagement.config,
        halt=halt_mod.OperatorHalt(engagement.root, engagement.db))


@pytest.fixture
def tool_run(tool_ctx):
    """A `tool_ctx` with a manual run already open.

    EVERY EGRESS TEST NEEDS ONE and the reason is not bookkeeping: `run_id`
    is what `record_exchange` attributes an exchange to and what
    `run.requests_issued` counts on. A context with no run open resolves
    `run_id` to None, writes an orphan exchange row, and silently counts
    nothing -- which is a coverage figure of zero for traffic that happened.
    """
    from hx import run as run_mod

    tool_ctx.run_id = run_mod.open_run(
        tool_ctx.conn, engagement_id=tool_ctx.engagement.id, kind="manual",
        safety_profile=tool_ctx.config.safety_profile)
    return tool_ctx


@pytest.fixture
def live_session(tool_ctx):
    """A `tool_ctx` with a fake bridge on `ctx.session` and an open `scan`
    run -- the bracket Ruling 9 makes `scan.run` require (`hx.scan.run`
    resolves its run via `current_run(kind='scan')`, which the tool layer
    must have already opened) and the bridge every `needs_egress` tool needs
    to get past the dispatcher's `no_session` guard.

    `FakeBridge` (`tests/test_probe.py`) is the project's one double for
    `BridgeServer.send`-shaped things; imported locally, matching this
    file's own `engagement` fixture, so this module keeps importing nothing
    with a side effect at collection time.
    """
    from hx import run as run_mod

    from tests.test_probe import FakeBridge

    tool_ctx.run_id = run_mod.open_run(
        tool_ctx.conn, engagement_id=tool_ctx.engagement.id, kind="scan",
        safety_profile=tool_ctx.config.safety_profile)
    tool_ctx.session = type("S", (), {"bridge": FakeBridge()})()
    return tool_ctx


@pytest.fixture
def staff_identity_config(engagement):
    """The engagement's config with one static identity, `staff`, declared.

    HERE RATHER THAN IN ONE TEST MODULE because three of Plan B's tasks need
    it: `hx.tools.live.ensure_identity` (Task 3), `http.replay_as` (Task 6)
    and `scan.run`'s identity argument (Task 7) all have to resolve a name
    against `Config.identities`, and a second hand-rolled declaration is a
    second set of field values free to drift from this one.

    BUILT BY `dataclasses.replace` OFF THE ENGAGEMENT'S OWN CONFIG, the way
    `tests/test_scan_probes.py`'s `_declaring` builds one, so `scope_include`
    still names the host the identity's `origins` bound the credential to --
    a config whose scope and whose origins disagreed would be a fixture
    testing something no operator could write.

    `value_from_env` NAMES A VARIABLE AND HOLDS NO VALUE. `HX_STAFF_TOKEN` is
    set by whichever test needs a credential to exist (`monkeypatch.setenv`),
    which is also what proves `hx.identity.resolve` reads the environment
    rather than the config -- spec principle 5, and the reason a `Config` can
    be written to disk at all.
    """
    import dataclasses

    staff = config_mod.Identity(
        id="staff", strategy="static",
        inject=config_mod.Inject(header="Cookie",
                                 value_from_env="HX_STAFF_TOKEN"),
        liveness=config_mod.Liveness(path="/account", expect_body="Sign out",
                                     expect_absent="Sign in"),
        origins=("https://app.test/",))
    return dataclasses.replace(engagement.config, identities={"staff": staff})


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
