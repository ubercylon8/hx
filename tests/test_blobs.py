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
    """All directories created by BlobStore should be 0o700, even if parent doesn't exist."""
    # Create BlobStore at a path where parent doesn't exist
    nested_root = tmp_path / "nonexistent" / "nested" / "root"
    store = BlobStore(nested_root)
    digest, _ = store.put(b"test data")

    # Check that tmp directory and all parents up to nested_root are 0o700
    tmp_dir = nested_root / "tmp"
    for path in [tmp_dir, nested_root, tmp_path / "nonexistent" / "nested"]:
        if path.is_dir():
            mode = path.stat().st_mode & 0o777
            assert mode == 0o700, f"Directory {path} has mode {oct(mode)}, expected 0o700"
