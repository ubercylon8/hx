"""The durable operator halt.

Spec S4 gives the kill switch three independent paths -- a `halt` frame, the
STOP button in the harness's Burp suite tab, and a sentinel file the extension
polls -- so that any one of them works when the others are wedged. This module
owns the sentinel file and makes the frame survive a restart.

An operator halt is durable: it is a row in the engagement store AND a file on
disk, so it survives the harness dying, Burp dying, or both. Two findings the
Plan 2 review left open live here: a second `hello` used to erase the halt,
and a halt did not survive a Burp restart -- precisely when someone has
already hit stop. A reconnect therefore does not clear it (the bridge
re-asserts `halt` after any peer's hello, before any configure), a `configure`
re-authorises scope and never issuance, and only `resume()` re-arms.

**Nothing here reads the database except `__init__`.** The bridge's read
thread asks `halted` and `reason` on every hello, and a connection from
`hx.store.db.connect` belongs to the thread that created it: used anywhere
else it raises `sqlite3.ProgrammingError`, which tests/test_halt.py proves by
doing it rather than asserting it in a comment. So the row is read once, at
construction, on the owning thread, and from then on the armed flag lives in
memory beside a sentinel file that costs one stat().

The writers (`halt`, `resume`) do touch the database and must be called from
the thread that opened it. `halt()` is ordered so that this cannot become a
failure to stop: see the comment on the method.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from hx.store.records import new_id

# The extension polls for this file by NAME in the engagement directory; the
# same path is passed to the jar as -Dhx.halt_sentinel.
SENTINEL_NAME = "HALTED"

# agent_action.tool values. Plan 1's schema has no halt table -- and adding
# one is a migration this plan does not do -- so the halt log lives in the
# only table that has an engagement, a nullable run, an actor, a timestamp and
# a free-text `why`. The state is the latest of these two rows, which also
# makes it an audit trail: who stopped the run, when, and why.
HALT_TOOL = "halt"
RESUME_TOOL = "resume"
ACTOR = "operator"


class HaltError(Exception):
    """The halt state cannot be read or established."""


def _now_us() -> int:
    return time.time_ns() // 1000


class OperatorHalt:
    def __init__(self, engagement_dir: Path, db: sqlite3.Connection) -> None:
        self.engagement_dir = Path(engagement_dir)
        self._db = db
        # halt() and resume() each write two places. The lock keeps a second
        # caller from interleaving between them and leaving the file saying
        # one thing and the row another.
        self._lock = threading.Lock()

        rows = db.execute("SELECT id FROM engagement").fetchall()
        if len(rows) != 1:
            # Same invariant `engagement.open_()` enforces: one engagement per
            # database. Guessing which one a halt belongs to is not an option.
            raise HaltError(
                f"expected exactly one engagement row in {engagement_dir}, "
                f"found {len(rows)}"
            )
        self._engagement_id = rows[0][0]

        row = db.execute(
            "SELECT tool, why FROM agent_action WHERE engagement_id = ?"
            " AND tool IN (?, ?) ORDER BY ts_us DESC, rowid DESC LIMIT 1",
            (self._engagement_id, HALT_TOOL, RESUME_TOOL),
        ).fetchone()
        # rowid breaks the tie as well as ts_us: two events inside the same
        # microsecond are possible, and the later INSERT is the later event.
        self._armed = row is not None and row[0] == HALT_TOOL
        self._reason = row[1] if self._armed else None

    # ---- state ---------------------------------------------------------

    @property
    def sentinel_path(self) -> Path:
        return self.engagement_dir / SENTINEL_NAME

    def _sentinel_present(self) -> bool:
        try:
            os.stat(self.sentinel_path)
            return True
        except FileNotFoundError:
            return False
        except OSError:
            # S4: "If it cannot be read -- permissions, a vanished directory,
            # an I/O error -- the extension treats that as halted. Unknown
            # state is stop." This side answers the same way.
            #
            # os.stat with two explicit branches, not Path.exists(): pathlib
            # decides for us which errno counts as "no", through a private
            # helper (`pathlib._ignore_error`) whose contents are an
            # implementation detail. On this interpreter EACCES propagates out
            # of Path.exists() and ENOENT returns False, which happens to be
            # right -- but a fail-closed answer must not rest on the contents
            # of a private list.
            return True

    @property
    def halted(self) -> bool:
        """True if either the store or the filesystem says stop.

        A union, not an agreement. An operator can `touch` the sentinel from a
        shell when the socket is dead or the agent has stopped responding --
        S4 names that as the reason the file exists -- and that halt has no
        row behind it. The reverse case is a harness that died between the two
        writes.
        """
        return self._armed or self._sentinel_present()

    @property
    def reason(self) -> str | None:
        if self._armed:
            return self._reason
        if not self._sentinel_present():
            return None
        try:
            text = self.sentinel_path.read_text(encoding="utf-8",
                                                errors="replace")
        except OSError:
            return f"{self.sentinel_path} exists but cannot be read"
        return text.split("\n")[0].strip() or f"{self.sentinel_path} exists"

    # ---- transitions ---------------------------------------------------

    def halt(self, reason: str) -> None:
        """Stop issuance, durably.

        The sentinel is written FIRST and the row second, deliberately. The
        file is the mechanism that actually stops the extension -- it polls it
        and it works when the bridge is dead -- while the row is what explains
        the stop afterwards. If the INSERT fails (a broken store, or this
        being called from a thread that does not own the connection) the halt
        is already in force and the exception says the audit line is missing.
        A failure to explain must not become a failure to stop.
        """
        # Collapsed to one line, not refused. codec.build_config_body refuses
        # a config value containing a newline rather than escaping it, and
        # that is right there because refusing a config value is the safe
        # answer; refusing to HALT over the formatting of a reason string is
        # the fail-open direction, so this one is normalised instead.
        one_line = " ".join(str(reason).split())
        with self._lock:
            self._write_sentinel(one_line)
            self._armed = True
            self._reason = one_line
            self._db.execute(
                "INSERT INTO agent_action(id, engagement_id, run_id, ts_us,"
                " actor, tool, why) VALUES(?,?,?,?,?,?,?)",
                (new_id("a"), self._engagement_id, None, _now_us(),
                 ACTOR, HALT_TOOL, one_line),
            )

    def resume(self) -> None:
        """Re-arm issuance. The only thing that lifts a halt.

        The mirror of halt(), under the same rule: every ordering failure
        leaves issuance STOPPED. The row goes in first, so a failure to write
        it leaves the sentinel in place and the halt standing; removing the
        file first and then failing would lift a halt with no record of who
        lifted it.
        """
        with self._lock:
            self._db.execute(
                "INSERT INTO agent_action(id, engagement_id, run_id, ts_us,"
                " actor, tool, why) VALUES(?,?,?,?,?,?,?)",
                (new_id("a"), self._engagement_id, None, _now_us(),
                 ACTOR, RESUME_TOOL, "operator resumed issuance"),
            )
            self._armed = False
            self._reason = None
            try:
                os.unlink(self.sentinel_path)
            except FileNotFoundError:
                pass

    # ---- the file ------------------------------------------------------

    def _write_sentinel(self, reason: str) -> None:
        """Create the sentinel atomically, at 0o600, never half-written.

        Same shape as `engagement._write_config_secure`, for the same reasons:
        O_EXCL at the final mode so the file never exists world-readable even
        for an instant, and a rename so a reader never sees a partial file.

        The extension keys on the file EXISTING, not on what is in it -- a
        reader that needed the content would have to decide what a truncated
        file means, and S4 has already decided that unreadable is halted. The
        two lines are for the human who finds the file: the reason, and the
        microsecond it was written.
        """
        tmp = self.engagement_dir / f".{uuid.uuid4().hex}.{SENTINEL_NAME}"
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(f"{reason}\n{_now_us()}\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.sentinel_path)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            Path(tmp).unlink(missing_ok=True)
            raise
        # The rename is atomic against a concurrent reader the moment it
        # returns; this fsync is what makes it survive a power cut as well.
        # The failure modes S4 names -- the harness dying, Burp dying -- do
        # not need it, but a halt is the one state worth the extra syscall.
        dir_fd = os.open(str(self.engagement_dir), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
