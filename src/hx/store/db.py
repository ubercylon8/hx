"""SQLite access for one engagement.

Every connection must apply the same pragmas. foreign_keys in particular is
OFF per-connection by default in SQLite, so a connection opened without it
silently ignores every REFERENCES clause in the schema.
"""
from __future__ import annotations

import sqlite3
from importlib import resources
from pathlib import Path

SCHEMA_VERSION = 1

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
    if readonly:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
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
