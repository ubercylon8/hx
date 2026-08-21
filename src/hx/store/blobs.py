"""Content-addressed blob storage, scoped to one engagement.

Blobs are partitioned per engagement rather than globally. Cross-engagement
dedupe would save little at 320 req/s of mostly-distinct bodies, and it would
make contractual data destruction impossible to perform correctly: deleting
client A's data must not corrupt client B's evidence.
"""
from __future__ import annotations

import hashlib
import os
import re
import uuid
from pathlib import Path

from hx.store.paths import secure_mkdir

_HEX64 = re.compile(r"[0-9a-f]{64}")


class CorruptBlob(Exception):
    """A blob's bytes do not match the digest or length they are stored under."""


class BlobStore:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.tmp = self.root / "tmp"
        secure_mkdir(self.tmp)

    def path_for(self, digest: str) -> Path:
        """Resolve a digest to its on-disk path.

        `digest` must be a bare 64-character lowercase hex sha256. Without
        this check, an absolute or `..`-laden string resets or escapes the
        join (`path_for("/etc/passwd")` returns `/etc/passwd` outright), and
        blob refs will arrive over the bridge from the JVM in Plan 2 -- an
        attacker-controlled string reaching this function is not hypothetical
        there.
        """
        if not _HEX64.fullmatch(digest):
            raise CorruptBlob(f"not a valid digest: {digest!r}")
        return self.root / digest[:2] / digest[2:4] / digest

    def put(self, data: bytes) -> tuple[str, int]:
        digest = hashlib.sha256(data).hexdigest()
        final = self.path_for(digest)
        if final.exists():
            try:
                if hashlib.sha256(final.read_bytes()).hexdigest() == digest:
                    return digest, len(data)
            except OSError:
                pass  # unreadable: repair it

        # Create directories with mode 0o700
        secure_mkdir(final.parent)

        # Create staging file with mode 0o600
        staging = self.tmp / f"{uuid.uuid4().hex}.part"
        fd = os.open(str(staging), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        except Exception:
            # The `with` block already closed fd via fdopen()'s __exit__ in
            # the common case (write/fsync failure inside the block); this
            # only catches fd surviving unclosed if fdopen() itself raised
            # before the file object existed to close it. Closing an
            # already-closed fd raises OSError (EBADF), which is the one
            # error worth swallowing here -- anything else should surface.
            try:
                os.close(fd)
            except OSError:
                pass
            staging.unlink(missing_ok=True)
            raise

        written = staging.read_bytes()
        if hashlib.sha256(written).hexdigest() != digest:
            staging.unlink(missing_ok=True)
            raise CorruptBlob(f"digest mismatch writing {digest}")

        os.replace(staging, final)
        os.chmod(final, 0o600)
        return digest, len(data)

    def get(self, digest: str, expected_len: int | None = None) -> bytes:
        path = self.path_for(digest)
        if not path.exists():
            raise CorruptBlob(f"blob {digest} missing")
        data = path.read_bytes()
        if expected_len is not None and len(data) != expected_len:
            raise CorruptBlob(
                f"blob {digest} length {len(data)} != expected {expected_len}"
            )
        if hashlib.sha256(data).hexdigest() != digest:
            raise CorruptBlob(f"blob {digest} failed digest verification")
        return data
