import stat
from pathlib import Path

from hx.store.paths import secure_mkdir


def test_secure_mkdir_creates_nested_dirs_at_0o700(tmp_path: Path):
    target = tmp_path / "a" / "b" / "c"
    secure_mkdir(target)
    for p in (tmp_path / "a", tmp_path / "a" / "b", target):
        assert stat.S_IMODE(p.stat().st_mode) == 0o700


def test_secure_mkdir_leaves_a_preexisting_ancestor_alone(tmp_path: Path):
    """Regression test for the shared helper: only directories this call
    creates are touched. A directory that already exists belongs to the
    caller's filesystem, and re-permissioning it would silently change
    something the helper does not own. This is the destructive recursive
    chmod fixed earlier in the branch, guarded here for the consolidated
    helper too."""
    ancestor = tmp_path / "preexisting"
    ancestor.mkdir(mode=0o755)

    secure_mkdir(ancestor / "sub" / "leaf")

    assert stat.S_IMODE(ancestor.stat().st_mode) == 0o755, "pre-existing ancestor was modified"
    assert stat.S_IMODE((ancestor / "sub").stat().st_mode) == 0o700
    assert stat.S_IMODE((ancestor / "sub" / "leaf").stat().st_mode) == 0o700


def test_secure_mkdir_on_an_already_existing_target_does_not_raise(tmp_path: Path):
    target = tmp_path / "already"
    target.mkdir(mode=0o700)
    secure_mkdir(target)  # must not raise
    assert stat.S_IMODE(target.stat().st_mode) == 0o700
