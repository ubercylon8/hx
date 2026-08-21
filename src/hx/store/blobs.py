"""Content-addressed blob storage, scoped to one engagement.

Blobs are partitioned per engagement rather than globally. Cross-engagement
dedupe would save little at 320 req/s of mostly-distinct bodies, and it would
make contractual data destruction impossible to perform correctly: deleting
client A's data must not corrupt client B's evidence.
"""
from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path


class CorruptBlob(Exception):
    """A blob's bytes do not match the digest or length they are stored under."""


class BlobStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.tmp = self.root / "tmp"
        self.tmp.mkdir(parents=True, exist_ok=True)
        os.chmod(self.tmp, 0o700)
        # Ensure all parent directories are also 0o700
        for parent in self.tmp.parents:
            if parent == self.root:
                os.chmod(parent, 0o700)

    def path_for(self, digest: str) -> Path:
        return self.root / digest[:2] / digest[2:4] / digest

    def put(self, data: bytes) -> tuple[str, int]:
        digest = hashlib.sha256(data).hexdigest()
        final = self.path_for(digest)
        if final.exists() and final.stat().st_size == len(data):
            return digest, len(data)

        # Create directories with mode 0o700
        final.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(final.parent, 0o700)
        # Ensure all parent directories are also 0o700
        for parent in final.parent.parents:
            if parent == self.root:
                os.chmod(parent, 0o700)
                break
            os.chmod(parent, 0o700)

        # Create staging file with mode 0o600
        staging = self.tmp / f"{uuid.uuid4().hex}.part"
        fd = os.open(str(staging), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        except Exception:
            # Clean up the file descriptor if something goes wrong
            try:
                os.close(fd)
            except Exception:
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
