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
