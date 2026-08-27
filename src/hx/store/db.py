"""SQLite access for one engagement.

Every connection must apply the same pragmas. foreign_keys in particular is
OFF per-connection by default in SQLite, so a connection opened without it
silently ignores every REFERENCES clause in the schema.
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from importlib import resources
from pathlib import Path

from hx.store.paths import secure_mkdir

# 5 -> 6 (2026-08-25): `denial.kind` gained 'credential' and
# `surface.discovered_by` lost its DEFAULT. Both land inside Plan 4's branch,
# on top of the 4 -> 5 bump that added `denial.via` a commit earlier -- and
# reusing 5 for them would have made two INCOMPATIBLE schemas share one
# version number, since a database created at that earlier commit already
# exists on disk. Such a file refuses every `credential` denial this code now
# writes: its CHECK has no such value, so SQLite rejects the INSERT. It also
# still answers 'proxy' for any writer that omits `surface.discovered_by`
# rather than failing, which is the guess the DEFAULT was removed to stop.
# `engagement.open_`'s comparison against this constant is the only thing in
# the tree that can notice either.
SCHEMA_VERSION = 6

TABLES: tuple[str, ...] = (
    "engagement",
    "scope_version",
    "authorization",
    "run",
    "surface",
    "exchange",
    "check_run",
    "finding",
    "finding_observation",
    "finding_status_event",
    "evidence",
    "agent_action",
    "denial",
    "quarantine",
)


def connect(path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    path = Path(path)
    if readonly:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    else:
        secure_mkdir(path.parent)
        if not path.exists():
            # Pre-create at the final mode so the database file never exists
            # on disk at a looser permission than 0o600, even for an
            # instant -- the create-then-chmod window this closes is the
            # same class of bug fixed for config.yaml.
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        else:
            # Only ever TIGHTEN an existing file's permissions, never widen
            # them. `path.chmod(0o600)` unconditionally healed a
            # deliberately-restricted file (e.g. 0o400 on a sealed
            # engagement) back to writable on every open -- making
            # `engagement.status = 'sealed'` unenforceable at the
            # filesystem level.
            mode = path.stat().st_mode & 0o777
            if mode & 0o077:
                path.chmod(mode & 0o700)
        conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    if not readonly:
        # journal_mode is a write to the database header, so it raises
        # OperationalError on a read-only connection. The mode is a property
        # of the file, already set by the writer, so readers inherit it.
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _schema_sql() -> str:
    return resources.files("hx.store").joinpath("schema.sql").read_text(encoding="utf-8")


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_schema_sql())
    conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")


@contextmanager
def transaction(conn: sqlite3.Connection):
    """Group statements into one all-or-nothing unit.

    Connections from `connect()` are autocommit (isolation_level=None), so
    any multi-statement write that is not wrapped in an explicit
    BEGIN/COMMIT is not atomic -- a failure partway through leaves whatever
    already ran committed. Exactly one place in this codebase remembered
    that on its own before this helper existed; more call sites were expected
    in later plans, and this is cheap insurance against one of them
    forgetting. `hx.capture.on_exchange` is the first of those and did forget
    -- it wrote four statements unwrapped, and `upsert_surface` failing left a
    committed exchange row with a NULL `surface_id` behind it.
    """
    conn.execute("BEGIN")
    try:
        yield conn
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass  # transaction already gone; do not mask the original error
        raise
    else:
        conn.execute("COMMIT")
