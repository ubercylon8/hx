"""Shared filesystem security primitives.

A duplicated security primitive drifts -- `db.py`, `blobs.py` and
`engagement.py` each grew their own "create a directory safely" idiom during
this branch. This module is the one place left.
"""
from __future__ import annotations

import os
from pathlib import Path


def secure_mkdir(path: Path) -> None:
    """Create `path` and any missing ancestors, each at mode 0o700.

    Only directories this call creates are touched: a directory that already
    exists belongs to the caller's filesystem, not to this store, and
    re-permissioning it would silently change something we do not own.

    Each missing level is created with an explicit mode
    (`os.mkdir(p, 0o700)`) rather than `mkdir(parents=True)` followed by a
    chmod pass over what got created. That removes both the
    write-at-umask-then-chmod window and the deferred TOCTOU of fixing
    permissions up after the fact -- the directory never exists on disk at a
    looser mode than 0o700, even for an instant.
    """
    path = Path(path)
    missing: list[Path] = []
    probe = path
    while not probe.exists():
        missing.append(probe)
        if probe.parent == probe:  # reached the filesystem root
            break
        probe = probe.parent

    for created in reversed(missing):
        os.mkdir(created, 0o700)
