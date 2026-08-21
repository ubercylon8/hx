from pathlib import Path

import pytest

from hx.store.blobs import BlobStore, CorruptBlob


def test_put_then_get_round_trips(tmp_path: Path):
    store = BlobStore(tmp_path)
    digest, length = store.put(b"hello burp")
    assert length == 10
    assert store.get(digest) == b"hello burp"


def test_identical_content_stored_once(tmp_path: Path):
    store = BlobStore(tmp_path)
    d1, _ = store.put(b"same bytes")
    d2, _ = store.put(b"same bytes")
    assert d1 == d2
    assert sum(1 for p in tmp_path.rglob("*") if p.is_file()) == 1


def test_get_verifies_length(tmp_path: Path):
    store = BlobStore(tmp_path)
    digest, length = store.put(b"abcdef")
    with pytest.raises(CorruptBlob):
        store.get(digest, expected_len=999)


def test_truncated_blob_on_disk_is_detected(tmp_path: Path):
    """A torn write must fail loudly, not poison every future identical body."""
    store = BlobStore(tmp_path)
    digest, _ = store.put(b"a" * 500)
    store.path_for(digest).write_bytes(b"a" * 200)
    with pytest.raises(CorruptBlob):
        store.get(digest)


def test_large_blob_round_trips(tmp_path: Path):
    store = BlobStore(tmp_path)
    payload = bytes(range(256)) * 8000  # ~2 MB, larger than a Burp response
    digest, length = store.put(payload)
    assert length == len(payload)
    assert store.get(digest, expected_len=length) == payload


def test_no_temp_files_left_behind(tmp_path: Path):
    store = BlobStore(tmp_path)
    store.put(b"x" * 1000)
    assert list((tmp_path / "tmp").glob("*")) == []


def test_directories_created_with_mode_0o700(tmp_path: Path):
    """Directories must be created with mode 0o700 for proper access control."""
    store = BlobStore(tmp_path)
    digest, _ = store.put(b"test data")

    # Check that tmp directory is 0o700
    tmp_dir_mode = (tmp_path / "tmp").stat().st_mode & 0o777
    assert tmp_dir_mode == 0o700, f"tmp directory mode is {oct(tmp_dir_mode)}, expected 0o700"

    # Check that digest directories are 0o700
    blob_path = store.path_for(digest)
    for parent in [blob_path.parent, blob_path.parent.parent]:
        parent_mode = parent.stat().st_mode & 0o777
        assert parent_mode == 0o700, f"Directory {parent} mode is {oct(parent_mode)}, expected 0o700"


def test_blob_file_created_with_mode_0o600(tmp_path: Path):
    """Blob files must be created with mode 0o600."""
    store = BlobStore(tmp_path)
    digest, _ = store.put(b"sensitive client data")

    blob_path = store.path_for(digest)
    file_mode = blob_path.stat().st_mode & 0o777
    assert file_mode == 0o600, f"Blob file mode is {oct(file_mode)}, expected 0o600"


def test_put_repairs_a_same_length_corruption(tmp_path: Path):
    """The nastier torn write: same length, wrong bytes."""
    store = BlobStore(tmp_path)
    digest, _ = store.put(b"a" * 500)
    store.path_for(digest).write_bytes(b"b" * 500)  # same length, wrong content

    again, length = store.put(b"a" * 500)
    assert again == digest and length == 500
    assert store.get(digest) == b"a" * 500, "put() did not repair the blob"


def test_nested_directory_creation_secures_all_levels(tmp_path: Path):
    """All directories created by BlobStore should be 0o700, even if parents don't exist."""
    # Create BlobStore at a path where parents don't exist
    nested_root = tmp_path / "nonexistent" / "nested" / "root"
    store = BlobStore(nested_root)
    digest, _ = store.put(b"test data")

    # Check that directories created by BlobStore are 0o700
    tmp_dir = nested_root / "tmp"
    for path in [tmp_dir, nested_root, tmp_path / "nonexistent" / "nested"]:
        mode = path.stat().st_mode & 0o777
        assert mode == 0o700, f"Created directory {path} has mode {oct(mode)}, expected 0o700"


# --- M1: path_for() must validate the digest format, not treat an
# arbitrary string as a filesystem path ---


def test_path_for_rejects_absolute_path_escape(tmp_path: Path):
    """Without a format check, an absolute component resets the join --
    `path_for("/etc/passwd")` used to return `/etc/passwd` outright,
    escaping the engagement root entirely."""
    store = BlobStore(tmp_path)
    with pytest.raises(CorruptBlob):
        store.path_for("/etc/passwd")


def test_path_for_rejects_relative_path_escape(tmp_path: Path):
    store = BlobStore(tmp_path)
    with pytest.raises(CorruptBlob):
        store.path_for("../../etc/passwd")


def test_path_for_rejects_malformed_digest(tmp_path: Path):
    store = BlobStore(tmp_path)
    with pytest.raises(CorruptBlob):
        store.path_for("abc")


def test_path_for_accepts_a_real_digest(tmp_path: Path):
    store = BlobStore(tmp_path)
    digest, _ = store.put(b"hello")
    assert store.path_for(digest) == store.root / digest[:2] / digest[2:4] / digest


def test_get_rejects_malformed_digest_without_touching_disk(tmp_path: Path):
    """get() must fail the format check before it ever reads a file --
    otherwise a malformed digest is a file-existence/size oracle via the
    exception message."""
    store = BlobStore(tmp_path)
    with pytest.raises(CorruptBlob):
        store.get("/etc/passwd")


def test_preexisting_directories_left_alone(tmp_path: Path):
    """Regression test: BlobStore must not chmod pre-existing directories."""
    # Create a pre-existing directory with mode 0o755
    preexisting = tmp_path / "preexisting"
    preexisting.mkdir(mode=0o755)

    # Create BlobStore in a subdirectory beneath it
    store_root = preexisting / "store" / "root"
    store = BlobStore(store_root)
    store.put(b"test data")

    # Assert the pre-existing directory was NOT modified
    mode = preexisting.stat().st_mode & 0o777
    assert mode == 0o755, f"Pre-existing directory was modified to {oct(mode)}, expected 0o755"
