import os
import sqlite3
import stat
import threading

import pytest

from hx import halt as halt_mod
from hx.store import db as db_mod
from hx.store.paths import secure_mkdir


@pytest.fixture
def engagement(tmp_path):
    root = tmp_path / "engagement"
    secure_mkdir(root)
    conn = db_mod.connect(root / "hx.db")
    db_mod.init_schema(conn)
    conn.execute("INSERT INTO engagement(id, name, client, created_us, status)"
                 " VALUES('e-1','Example','Example Ltd',1,'active')")
    yield root, conn
    conn.close()


def test_a_fresh_engagement_is_not_halted(engagement):
    root, conn = engagement
    h = halt_mod.OperatorHalt(root, conn)
    assert h.halted is False
    assert h.reason is None
    assert not h.sentinel_path.exists()


def test_halt_writes_the_sentinel_and_the_row(engagement):
    root, conn = engagement
    h = halt_mod.OperatorHalt(root, conn)
    h.halt("client called: stop everything")

    assert h.halted is True
    assert h.reason == "client called: stop everything"
    assert h.sentinel_path == root / "HALTED"
    assert stat.S_IMODE(h.sentinel_path.stat().st_mode) == 0o600
    assert h.sentinel_path.read_text().splitlines()[0] == "client called: stop everything"

    row = conn.execute(
        "SELECT actor, tool, why FROM agent_action WHERE tool='halt'").fetchone()
    assert row["actor"] == "operator"
    assert row["why"] == "client called: stop everything"


def test_a_halt_survives_the_harness_dying(engagement):
    root, conn = engagement
    halt_mod.OperatorHalt(root, conn).halt("client called: stop everything")
    revived = halt_mod.OperatorHalt(root, conn)
    assert revived.halted is True
    assert revived.reason == "client called: stop everything"


def test_a_halt_survives_the_store_being_unavailable(engagement):
    root, conn = engagement
    h = halt_mod.OperatorHalt(root, conn)
    h.halt("client called: stop everything")
    conn.execute("DELETE FROM agent_action")
    assert halt_mod.OperatorHalt(root, conn).halted is True


def test_a_sentinel_created_from_a_shell_is_a_halt(engagement):
    root, conn = engagement
    h = halt_mod.OperatorHalt(root, conn)
    h.sentinel_path.write_text("socket was dead, stopped by hand\n")
    assert h.halted is True
    assert h.reason == "socket was dead, stopped by hand"


@pytest.mark.skipif(os.getuid() == 0, reason="root ignores directory permissions")
def test_a_sentinel_that_cannot_be_read_is_a_halt(engagement):
    root, conn = engagement
    h = halt_mod.OperatorHalt(root, conn)
    h.sentinel_path.write_text("stopped by hand\n")
    os.chmod(root, 0o000)
    try:
        assert h.halted is True
        assert "cannot be read" in h.reason
    finally:
        os.chmod(root, 0o700)


def test_only_resume_lifts_it(engagement):
    root, conn = engagement
    h = halt_mod.OperatorHalt(root, conn)
    h.halt("scope was wrong")
    assert halt_mod.OperatorHalt(root, conn).halted is True
    h.resume()
    assert h.halted is False
    assert h.reason is None
    assert not h.sentinel_path.exists()
    assert halt_mod.OperatorHalt(root, conn).halted is False
    assert conn.execute("SELECT COUNT(*) FROM agent_action WHERE tool='resume'").fetchone()[0] == 1


def test_resume_clears_a_shell_created_sentinel(engagement):
    root, conn = engagement
    h = halt_mod.OperatorHalt(root, conn)
    h.sentinel_path.write_text("stopped by hand\n")
    h.resume()
    assert h.halted is False


def test_the_sentinel_is_written_before_the_row(engagement):
    root, conn = engagement
    h = halt_mod.OperatorHalt(root, conn)

    class Broken:
        def execute(self, *a, **k):
            raise sqlite3.ProgrammingError("SQLite objects created in a thread")

    h._db = Broken()
    with pytest.raises(sqlite3.ProgrammingError):
        h.halt("client called: stop everything")
    assert h.halted is True
    assert h.sentinel_path.exists()


def test_halted_and_reason_never_touch_the_database(engagement):
    root, conn = engagement
    h = halt_mod.OperatorHalt(root, conn)
    h.halt("client called: stop everything")
    out = {}

    def read_it():
        try:
            out["halted"] = h.halted
            out["reason"] = h.reason
        except BaseException as exc:
            out["exc"] = exc

    t = threading.Thread(target=read_it)
    t.start()
    t.join(timeout=5)
    assert "exc" not in out, out
    assert out["halted"] is True
    assert out["reason"] == "client called: stop everything"


def test_the_store_connection_really_is_thread_confined(engagement):
    root, conn = engagement
    out = {}

    def query():
        try:
            conn.execute("SELECT id FROM engagement").fetchone()
        except BaseException as exc:
            out["exc"] = exc

    t = threading.Thread(target=query)
    t.start()
    t.join(timeout=5)
    assert isinstance(out.get("exc"), sqlite3.ProgrammingError), out


def test_a_reason_with_newlines_still_halts(engagement):
    root, conn = engagement
    h = halt_mod.OperatorHalt(root, conn)
    h.halt("client called\nstop everything\n")
    assert h.halted is True
    assert h.reason == "client called stop everything"
    assert len(h.sentinel_path.read_text().splitlines()) == 2


def test_a_store_with_no_engagement_row_is_refused(tmp_path):
    root = tmp_path / "empty"
    secure_mkdir(root)
    conn = db_mod.connect(root / "hx.db")
    db_mod.init_schema(conn)
    try:
        with pytest.raises(halt_mod.HaltError, match="exactly one engagement"):
            halt_mod.OperatorHalt(root, conn)
    finally:
        conn.close()


def _fd_double_close_probe(monkeypatch, run):
    """Run `run()` with a write that fails, and report which fds were closed.

    Returns (fds_opened_by_the_writer, fds_closed_by_hand). The claim under
    test is that the second contains none of the first: once `os.fdopen` has
    the descriptor, the file object closes it during unwinding and a second
    close by hand lands on whatever number the OS has handed out since.
    """
    opened: list[int] = []
    closed: list[int] = []
    real_open, real_close = os.open, os.close

    def spy_open(*a, **kw):
        fd = real_open(*a, **kw)
        opened.append(fd)
        return fd

    def spy_close(fd, *a, **kw):
        closed.append(fd)
        return real_close(fd, *a, **kw)

    def boom(*a, **kw):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "open", spy_open)
    monkeypatch.setattr(os, "close", spy_close)
    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(OSError):
        run()
    return opened, closed


def test_a_failed_sentinel_write_does_not_close_a_descriptor_twice(engagement,
                                                                   monkeypatch):
    """S4's "stop by hand" path must not close somebody else's file.

    `_write_sentinel` opened a descriptor, handed it to `os.fdopen`, and
    wrapped BOTH in one try whose except arm called `os.close(fd)`. The file
    object had already closed it on the way out, so that call landed on a
    descriptor this code no longer owned.

    DEMONSTRATED, outside this suite, in the shape the arm actually runs:

        opened fd=4
        os.close(4) -> OSError 9 (EBADF)        # before: caught, shrugged off

        ...and with one intervening open() in that window:
        opened fd=4;  another open() handed out fd=4   <-- THE SAME NUMBER
        os.close(4) succeeded;  fstat(fd=4) -> EBADF

    The second is the one that matters, and nothing about the first prevents
    it. The bridge's accept loop opens sockets continuously, so the window is
    not hypothetical -- it is the ordinary state of a running harness.

    MEASURED with the pre-fix files and these tests: `opened [15], closed by
    hand [15]`. With the pre-fix files and the tests as they were, 38 passed.
    """
    root, conn = engagement
    h = halt_mod.OperatorHalt(root, conn)
    opened, closed = _fd_double_close_probe(
        monkeypatch, lambda: h.halt("the operator stopped the run"))

    assert opened, "the probe never saw an open(); it is not measuring anything"
    assert [fd for fd in closed if fd in opened] == [], (
        f"a descriptor os.fdopen already closed was closed again: "
        f"opened {opened}, closed by hand {closed}")
    # ...and the guard did not cost the cleanup it was tangled up with.
    assert list(root.glob(".*")) == [], "a temp sentinel was left behind"
    assert not h.sentinel_path.exists()


def test_a_failed_config_write_does_not_close_a_descriptor_twice(tmp_path,
                                                                 monkeypatch):
    """`engagement._write_config_secure` had the identical shape, and
    `halt.py`'s comment says so in as many words. Fixed together and tested
    together -- one of them fixed alone is the pair drifting."""
    from hx import engagement as engagement_mod

    target = tmp_path / "config.yaml"
    opened, closed = _fd_double_close_probe(
        monkeypatch,
        lambda: engagement_mod._write_config_secure(target, "name: x\n"))

    assert opened, "the probe never saw an open(); it is not measuring anything"
    assert [fd for fd in closed if fd in opened] == [], (
        f"a descriptor os.fdopen already closed was closed again: "
        f"opened {opened}, closed by hand {closed}")
    assert list(tmp_path.glob(".*")) == [], "a temp config was left behind"
    assert not target.exists()
