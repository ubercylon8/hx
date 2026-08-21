"""Engagement lifecycle.

The engagement is the unit of isolation: its own directory, its own database,
its own blob tree. Nothing is shared between engagements, so client A's bytes
cannot reach client B's report and contractual data destruction is a single
`rm -rf` of one directory.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from hx import config as config_mod
from hx.store import blobs as blobs_mod
from hx.store import db as db_mod
from hx.store.paths import secure_mkdir


class EngagementError(Exception):
    """The engagement directory is missing, malformed, or already present."""


def now_us() -> int:
    return time.time_ns() // 1000


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@dataclass
class Engagement:
    id: str
    root: Path
    config: config_mod.Config
    db: sqlite3.Connection
    blobs: blobs_mod.BlobStore


def _write_config_secure(path: Path, text: str) -> None:
    """Atomically replace `path` with `text`, never at a looser mode than
    0o600 and never leaving a half-written file behind.

    Used for both first creation (`create()`) and every subsequent rewrite
    (`record_scope_version()`). A bare `write_text()` -- whether creating the
    file or truncating an existing one -- has no temp file, no fsync, and no
    atomic rename: a process killed mid-write can leave `config.yaml`
    truncated, or (worse) leave it as valid YAML with every required key
    present but a shorter `dangerous_paths` list, since `dumps()` emits that
    key near the end. The blob store already does temp -> fsync -> verify ->
    `os.replace` for a response body; the file defining what is contractually
    permitted to touch gets no less.

    The temp file is created with `O_EXCL` at the final 0o600 mode, so it is
    never briefly world-readable either.
    """
    path = Path(path)
    # Hidden, uuid-qualified, but same trailing name as the target: a
    # collision-proof temp name in the same directory (so the final
    # os.replace stays on one filesystem and is atomic).
    tmp = path.parent / f".{uuid.uuid4().hex}.{path.name}"
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        Path(tmp).unlink(missing_ok=True)
        raise


def _record_scope(
    conn: sqlite3.Connection,
    engagement_id: str,
    cfg: config_mod.Config,
    *,
    author: str,
    reason: str,
) -> str:
    yaml_text = config_mod.dumps(cfg)
    sv_id = _new_id("sv")
    conn.execute(
        "INSERT INTO scope_version(id, engagement_id, yaml, sha256,"
        " effective_from_us, author, reason) VALUES(?,?,?,?,?,?,?)",
        (
            sv_id,
            engagement_id,
            yaml_text,
            hashlib.sha256(yaml_text.encode("utf-8")).hexdigest(),
            now_us(),
            author,
            reason,
        ),
    )
    return sv_id


def _create_engagement_and_scope(
    conn: sqlite3.Connection,
    eng_id: str,
    cfg: config_mod.Config,
    config_path: str,
    *,
    author: str,
    reason: str,
) -> str:
    """Insert the engagement row and its initial scope version atomically.

    `db.connect` uses `isolation_level=None` (autocommit), so without an
    explicit transaction the engagement INSERT commits immediately and a
    failure while recording scope leaves an engagement with no authorisation
    record -- exactly the state the design says must be impossible ("what
    was in scope when request X was issued" must always be answerable).
    """
    with db_mod.transaction(conn):
        conn.execute(
            "INSERT INTO engagement(id, name, client, created_us, status, config_path)"
            " VALUES(?,?,?,?,?,?)",
            (eng_id, cfg.name, cfg.client, now_us(), "active", config_path),
        )
        sv_id = _record_scope(conn, eng_id, cfg, author=author, reason=reason)
    return sv_id


def create(root: Path, cfg: config_mod.Config, *, author: str) -> Engagement:
    root = Path(root)
    if root.exists():
        raise EngagementError(f"engagement directory already exists: {root}")

    created_root = False
    conn: sqlite3.Connection | None = None
    try:
        secure_mkdir(root)
        created_root = True
        (root / "exports").mkdir(mode=0o700)

        _write_config_secure(root / "config.yaml", config_mod.dumps(cfg))

        conn = db_mod.connect(root / "hx.db")
        db_mod.init_schema(conn)

        eng_id = _new_id("e")
        _create_engagement_and_scope(
            conn,
            eng_id,
            cfg,
            str(root / "config.yaml"),
            author=author,
            reason="engagement created",
        )
        blobs = blobs_mod.BlobStore(root / "blobs")
    except Exception:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        # Only remove a directory this call actually created -- deleting one
        # we did not create is the destructive-chmod bug wearing a different
        # hat. Without this, any failure above strands the directory, and
        # every retry dies on "already exists".
        if created_root and root.exists():
            shutil.rmtree(root, ignore_errors=True)
        raise

    return Engagement(id=eng_id, root=root, config=cfg, db=conn, blobs=blobs)


def open_(root: Path) -> Engagement:
    root = Path(root)
    if not (root / "hx.db").exists():
        raise EngagementError(f"no engagement at {root}")
    conn = db_mod.connect(root / "hx.db")
    try:
        # I6: a store opened by a different (and possibly incompatible)
        # schema version must fail loudly rather than run queries against
        # tables/triggers it does not actually have. The migration runner
        # itself is a later plan's problem; this guard only refuses to
        # pretend compatibility that was never verified.
        found_version = conn.execute("PRAGMA user_version").fetchone()[0]
        if found_version != db_mod.SCHEMA_VERSION:
            raise EngagementError(
                f"engagement at {root} was created by a different version of "
                f"hx: on-disk schema version {found_version}, this hx expects "
                f"{db_mod.SCHEMA_VERSION}"
            )

        # I5: `engagement` is meant to hold exactly one row -- it is the
        # unit of isolation, and `quarantine` and every unqualified lookup
        # here presume a single authoritative id. `LIMIT 1` with no
        # `ORDER BY` would pick an arbitrary row if a second one ever got
        # in; fetch all of them and refuse to guess.
        rows = conn.execute("SELECT id FROM engagement").fetchall()
        if len(rows) != 1:
            raise EngagementError(
                f"expected exactly one engagement row in {root}, found {len(rows)}"
            )
        row = rows[0]

        config = config_mod.load(root / "config.yaml")

        # I2: config.yaml and the recorded scope of record must never be
        # allowed to silently diverge -- a hand edit to the file would
        # otherwise become the live scope while the audit history (and,
        # later, the recorded `scope_version_id` stamped on every request)
        # says something else. There is no legitimate hand-edit workflow in
        # this store: `record_scope_version` is the API, so divergence
        # raises rather than warns.
        latest_scope = conn.execute(
            "SELECT yaml FROM scope_version"
            " ORDER BY effective_from_us DESC, rowid DESC LIMIT 1"
        ).fetchone()
        if latest_scope is not None:
            on_disk = (root / "config.yaml").read_text(encoding="utf-8")
            if on_disk != latest_scope["yaml"]:
                raise EngagementError(
                    f"{root / 'config.yaml'} diverges from the recorded scope "
                    "of record: its contents do not match the latest row in "
                    "scope_version. Restore config.yaml from that row, or "
                    "re-record the change through record_scope_version()."
                )

        blobs = blobs_mod.BlobStore(root / "blobs")
    except Exception:
        # Any failure past this point (missing config.yaml, a malformed
        # config, BlobStore init) must not leak the connection -- relying on
        # refcounting to eventually close it is not acceptable for a public
        # API, since a caller holding the exception (a CLI logging the
        # traceback, pytest) keeps the handle open indefinitely.
        conn.close()
        raise
    return Engagement(id=row["id"], root=root, config=config, db=conn, blobs=blobs)


def record_scope_version(eng: Engagement, *, author: str, reason: str) -> str:
    """Append a new scope version. Never updates an existing row."""
    sv_id = _record_scope(eng.db, eng.id, eng.config, author=author, reason=reason)
    _write_config_secure(eng.root / "config.yaml", config_mod.dumps(eng.config))
    return sv_id
