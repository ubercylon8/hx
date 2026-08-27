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

from hx.store import db as db_mod


@pytest.fixture
def engagement_conn():
    """An in-memory store with the schema applied and one engagement row.

    `sqlite3.connect(":memory:")` directly, not `db_mod.connect` -- that one
    takes a real path, pre-creates the file at 0600 and does the WAL/pragma
    dance a throwaway in-memory connection has no file to apply it to. The
    row factory is left at the sqlite3 default (a plain tuple), not
    `sqlite3.Row`: `tests/test_records_findings.py` compares a fetched row
    against a literal tuple, which `sqlite3.Row` does not equal.
    `foreign_keys` is deliberately left at SQLite's own default (OFF): tests
    that write a `finding` row reference run ids (`r-1`, `r-2`) and exchange
    ids (`x-1`, `x-2`) that name no real `run` or `exchange` row, on purpose,
    because run and exchange identity is not what this fixture's tests are
    about.
    """
    conn = sqlite3.connect(":memory:")
    db_mod.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e-1','T','T',1,'active')")
    yield conn
    conn.close()
