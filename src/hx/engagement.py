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


def _secure_mkdir(path: Path) -> None:
    """Create `path` and any missing ancestors, chmodding ONLY what we create.

    `path.mkdir(parents=True, mode=0o700)` applies `mode` to the leaf
    directory alone; any missing ancestor gets created at the process umask
    default, which can be world-readable -- turning a directory listing of
    every client under engagement into public information. A directory that
    already exists belongs to the user, not to this store: re-permissioning
    it would silently change their filesystem. Mirrors
    `hx.store.blobs.BlobStore._secure_dir`.
    """
    missing = []
    probe = path
    while not probe.exists():
        missing.append(probe)
        if probe.parent == probe:  # reached the filesystem root
            break
        probe = probe.parent

    path.mkdir(parents=True, exist_ok=True)
    for created in reversed(missing):
        os.chmod(created, 0o700)


def _write_config_secure(path: Path, text: str) -> None:
    """Write `path` so it never exists at a looser mode than 0o600.

    `write_text()` followed by `os.chmod(..., 0o600)` leaves the file at the
    umask default (typically 0o644) between the two calls, world-readable
    while it holds scope and identity references. Opening with O_EXCL and
    the final mode up front closes that window entirely.
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


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
    conn.execute("BEGIN")
    try:
        conn.execute(
            "INSERT INTO engagement(id, name, client, created_us, status, config_path)"
            " VALUES(?,?,?,?,?,?)",
            (eng_id, cfg.name, cfg.client, now_us(), "active", config_path),
        )
        sv_id = _record_scope(conn, eng_id, cfg, author=author, reason=reason)
    except Exception:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")
        return sv_id


def create(root: Path, cfg: config_mod.Config, *, author: str) -> Engagement:
    root = Path(root)
    if root.exists():
        raise EngagementError(f"engagement directory already exists: {root}")

    created_root = False
    conn: sqlite3.Connection | None = None
    try:
        _secure_mkdir(root)
        created_root = True
        (root / "exports").mkdir(mode=0o700)

        _write_config_secure(root / "config.yaml", config_mod.dumps(cfg))

        conn = db_mod.connect(root / "hx.db")
        db_mod.init_schema(conn)
        os.chmod(root / "hx.db", 0o600)  # redundant: db.connect already does this

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
        row = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()
        if row is None:
            raise EngagementError(f"engagement row missing in {root}")
        config = config_mod.load(root / "config.yaml")
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
    (eng.root / "config.yaml").write_text(
        config_mod.dumps(eng.config), encoding="utf-8"
    )
    return sv_id
