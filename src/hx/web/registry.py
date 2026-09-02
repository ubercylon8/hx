"""Which engagements exist under the base directory, and which names are real.

THE SCAN IS THE ALLOWLIST. A URL carries an engagement's DIRECTORY NAME, and
a name this scan did not return is a 404 -- not a sanitised path join, not a
`..` filter, not a `resolve()` compared against a prefix. Every one of those
is a blocklist wearing a helpful expression, and a blocklist fails to the
encoding its author did not think of. This one fails closed by construction:
the only names that resolve are names read off the filesystem.

Every connection opened here is READ-ONLY. `db.connect(readonly=True)` opens
`file:...?mode=ro`, so a write attempt raises `attempt to write a readonly
database` at the SQLite layer rather than depending on this module's
discipline. The store is evidence in a client engagement; a reader that
CANNOT write is a stronger claim than one that merely does not.
"""
from __future__ import annotations

import dataclasses
import sqlite3
from pathlib import Path

from hx.store import db as db_mod


@dataclasses.dataclass(frozen=True)
class Entry:
    """One engagement directory, openable or not.

    `problem` is the honest field. A store written by another schema version
    is a real thing to find on disk -- `engagement.open_` refuses it outright
    -- and the list screen must still render, naming what it found. An entry
    with a `problem` has `engagement_id is None` and no counts; nothing
    downstream may read those without checking.
    """

    name: str
    path: Path
    engagement_id: str | None
    client: str | None
    created_us: int | None
    status: str | None
    schema_version: int | None
    problem: str | None
    findings: dict
    runs: int


def _entry(path: Path) -> Entry:
    name = path.name
    blank = {"name": name, "path": path, "engagement_id": None,
             "client": None, "created_us": None, "status": None,
             "findings": {}, "runs": 0}
    try:
        conn = db_mod.connect(path / "hx.db", readonly=True)
    except sqlite3.Error as exc:
        return Entry(**blank, schema_version=None,
                     problem=f"cannot open the database: {exc}")
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version != db_mod.SCHEMA_VERSION:
            return Entry(
                **blank, schema_version=version,
                problem=f"schema version {version} on disk, this hx expects "
                        f"{db_mod.SCHEMA_VERSION}")
        rows = conn.execute(
            "SELECT id, client, created_us, status FROM engagement").fetchall()
        if len(rows) != 1:
            # The same invariant `engagement.open_` enforces. Guessing which
            # of two rows a screen is about is not an option.
            return Entry(**blank, schema_version=version,
                         problem=f"expected one engagement row, found {len(rows)}")
        row = rows[0]
        config_path = path / "config.yaml"
        try:
            # A CHEAP check -- a read, not a parse. `config_mod.load` would
            # also catch a MALFORMED file, but running it here means every
            # engagement's config is parsed on every index render just to
            # find out. The overview handler pays that cost for the one
            # engagement a request actually names; this only screens for
            # the file being missing or unreadable, the same class of fault
            # as the schema-version check above.
            config_path.read_bytes()
        except OSError as exc:
            return Entry(**blank, schema_version=version,
                         problem=f"cannot read {config_path}: {exc}")
        findings = {
            r[0]: r[1] for r in conn.execute(
                "SELECT severity, COUNT(*) FROM finding WHERE engagement_id=?"
                " GROUP BY severity", (row[0],)).fetchall()}
        runs = conn.execute(
            "SELECT COUNT(*) FROM run WHERE engagement_id=?",
            (row[0],)).fetchone()[0]
        return Entry(name=name, path=path, engagement_id=row[0],
                     client=row[1], created_us=row[2], status=row[3],
                     schema_version=version, problem=None,
                     findings=findings, runs=runs)
    except sqlite3.Error as exc:
        return Entry(**blank, schema_version=None,
                     problem=f"cannot read the database: {exc}")
    finally:
        conn.close()


def scan(base: Path) -> tuple[Entry, ...]:
    """Every engagement directory under `base`, in name order.

    Per request, not cached: an engagement created in another terminal
    should appear on refresh, and a directory listing is a syscall against a
    handful of entries.

    A directory with no `hx.db` is not an engagement and is skipped in
    silence -- an operator's notes folder living beside their engagements is
    ordinary, not an error.
    """
    base = Path(base)
    try:
        children = sorted(p for p in base.iterdir() if p.is_dir())
    except OSError:
        return ()
    return tuple(_entry(p) for p in children if (p / "hx.db").exists())


def lookup(base: Path, name: str) -> Entry | None:
    """The entry for one directory name, or None if the scan did not find it.

    Goes THROUGH `scan` rather than joining `base / name`, so there is one
    definition of "an engagement this app will answer about". A caller that
    built its own path would be a second definition, and the second one is
    always the one without the allowlist.
    """
    for entry in scan(base):
        if entry.name == name:
            return entry
    return None


def open_read(entry: Entry) -> sqlite3.Connection:
    """A fresh read-only connection to one engagement, for one request.

    FRESH, not cached, and the reason is mechanical: Starlette runs `def`
    endpoints in a threadpool, and `sqlite3` connections default to
    `check_same_thread=True`, so a cached connection raises
    `ProgrammingError` the moment two requests land on different threads.
    Opening a WAL reader is a file open. The app therefore holds no shared
    mutable state at all.
    """
    return db_mod.connect(entry.path / "hx.db", readonly=True)
