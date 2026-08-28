"""SQLite access for one engagement.

Every connection must apply the same pragmas. foreign_keys in particular is
OFF per-connection by default in SQLite, so a connection opened without it
silently ignores every REFERENCES clause in the schema.
"""
from __future__ import annotations

import os
import sqlite3
import uuid
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
#
# 6 -> 7 (2026-08-27, Task 6 fix round 2): `finding` gained `check_id`,
# additive and nullable -- no existing row's meaning changes, so this bump
# exists only to make an old store's absence of the column loud
# (`engagement.open_`'s version check) rather than something a later reader
# discovers by getting a `sqlite3.OperationalError: no such column` from a
# query it had every right to assume would work. See schema.sql's own
# comment on `finding.check_id` for why the column exists: it is NOT the
# same axis as `finding.issue_type_id`, and conflating the two was reachable
# without one.
# 7 -> 8 (2026-08-27, whole-branch review fix round A): NO DDL CHANGE, and
# the bump is deliberate anyway. `finding.dedupe_key`'s FORMAT changed --
# `records.dedupe_key` gained `issue_type_id` as its 2nd part (F1, HIGH) --
# so every key an older store holds is spelled in a format this code will
# never produce again. Nothing would fail: the UNIQUE constraint is on the
# string, so the first scan against such a store simply re-files every
# finding it already holds as new, with `first_seen_run` reset and the
# operator's triage stranded on the old row. That is precisely the silent
# outcome the 6 -> 7 comment above says this constant exists to make loud,
# and "the column list did not change" is not the test -- whether an older
# file still MEANS what this code assumes is. `engagement.open_`'s version
# check is the only thing in the tree that can notice.
SCHEMA_VERSION = 8

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


# Connections `transaction()` currently owns the OUTER `BEGIN` for, tracked
# by `id(conn)` rather than as an attribute ON the connection -- MEASURED:
# `sqlite3.Connection` (and a bare subclass of it) refuses arbitrary
# attribute assignment (`AttributeError: 'sqlite3.Connection' object has no
# attribute ...`) and is not weak-referenceable either, so there is no
# per-object place on the connection itself to record this. `id()`-keying is
# safe against id-reuse specifically because the only code that ever inserts
# a key also removes it, in a `finally`, before returning -- and for the
# whole of that window the caller holds a live reference to `conn` on the
# stack (it is the function's own argument), so the object cannot be
# garbage-collected and its id() handed to something else while the key is
# live. See F5 of the task-6 review for why this exists at all: `db.py`'s
# previous version asked `conn.in_transaction`, which cannot distinguish an
# OUTER `transaction()` call from sqlite3's own driver-implicit `BEGIN` (any
# connection not opened with `isolation_level=None` opens one before its
# first DML statement) -- and on such a connection, MEASURED, the old code
# took the SAVEPOINT path, `RELEASE`d, and never `COMMIT`ted: a loud
# `OperationalError` became silent data loss.
_OPEN_TRANSACTIONS: set[int] = set()


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

    REENTRANT, since Task 6. `conn.execute("BEGIN")` against a connection
    already inside a transaction raises
    `OperationalError: cannot start a transaction within a transaction` --
    MEASURED, the first time `hx.scan.run` called `records.record_evidence`
    (which wraps itself in `transaction(conn)`) from inside its own
    `_write_finding`, itself wrapped in `transaction(conn)`. A caller
    composing two already-atomic helpers into one atomic unit is exactly the
    "more call sites... in later plans" this docstring already predicted, so
    the helper -- not either call site -- is what learns to nest.

    WHICH PATH RUNS IS DECIDED BY OUR OWN `_OPEN_TRANSACTIONS` MARKER, NEVER
    BY `conn.in_transaction`. That flag reflects the DRIVER's state, not
    OURS, and the two are different questions: it is true both when this
    function opened the transaction and when sqlite3's own default isolation
    mode auto-began one behind our back, and `transaction()` needs to answer
    only the first. Outermost (this connection's id not in the marker set):
    a plain `BEGIN`/`COMMIT`/`ROLLBACK`, unchanged from before -- MEASURED
    against `hx.capture.on_exchange`, the merged, reviewed, non-nested
    caller, whose own tests (`tests/test_capture.py`) still pass unmodified.
    Nested (this connection's id already in the marker set, because an outer
    `transaction()` call is still on the stack): a named `SAVEPOINT`,
    released on success or rolled back to (then released) on failure, before
    re-raising -- so an inner failure undoes only the inner block's writes
    and the exception still propagates, while the OUTER transaction is left
    exactly as if the inner block had never run, free to retry or to fail on
    its own account.

    A connection that never goes through an outer `transaction()` call at
    all -- one where sqlite3's own driver opened an implicit transaction on
    its own -- is never in the marker set, so it always takes the OUTERMOST
    path here and gets the loud `OperationalError` a doubled `BEGIN`
    produces, exactly as before this function existed. That is deliberate:
    see F5 above for what happened when nesting was instead inferred from
    `conn.in_transaction`.

    RELEASING A SAVEPOINT IS NOT COMMITTING. SQLite only durably commits at
    the outermost `COMMIT` -- a `RELEASE` just folds the inner block's writes
    into the still-open outer transaction, so if the OUTER block later fails,
    its `ROLLBACK` undoes the released inner work too, not just what the
    outer block wrote itself. MEASURED both directions below (both are pinned
    in `tests/test_db.py`):

      * inner raises: the inner INSERT is gone, the exception propagates, and
        a SEPARATE inner transaction run afterwards on the same connection
        commits normally -- the savepoint stack was left clean, not wedged.
      * outer raises, after a nested transaction already ran and released
        cleanly inside it: the inner block's INSERT is ALSO gone. A savepoint
        path that let it survive would make a partial write look atomic,
        which is worse than the bug this replaces.
    """
    key = id(conn)
    if key not in _OPEN_TRANSACTIONS:
        _OPEN_TRANSACTIONS.add(key)
        try:
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
        finally:
            _OPEN_TRANSACTIONS.discard(key)
        return

    name = f"sp_{uuid.uuid4().hex}"
    conn.execute(f"SAVEPOINT {name}")
    try:
        yield conn
    except BaseException:
        try:
            conn.execute(f"ROLLBACK TO SAVEPOINT {name}")
            conn.execute(f"RELEASE SAVEPOINT {name}")
        except sqlite3.Error:
            pass  # savepoint already gone; do not mask the original error
        raise
    else:
        conn.execute(f"RELEASE SAVEPOINT {name}")
