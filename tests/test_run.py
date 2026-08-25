"""Run lifecycle, and in particular the run nobody closed.

The interesting cases here are all about a run that STOPPED rather than
ended. S5 is explicit that such a run must not render as a clean one, and a
report generated from a half-finished session that claims to be complete is
the worst output this project could produce.
"""
from __future__ import annotations

import pytest

from hx import run as run_mod
from hx.store import db as db_mod

ENG = "e-test"
HOUR = 3_600_000_000


@pytest.fixture
def conn(tmp_path):
    c = db_mod.connect(tmp_path / "hx.db")
    db_mod.init_schema(c)
    c.execute("INSERT INTO engagement(id, name, client, created_us, status)"
              " VALUES(?,'T','T',1,'active')", (ENG,))
    yield c
    c.close()


def _status(conn, run_id: str) -> str:
    return conn.execute("SELECT status FROM run WHERE id=?", (run_id,)).fetchone()[0]


class TestOpening:
    def test_a_run_opens_running(self, conn):
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        assert _status(conn, rid) == "running"

    def test_and_its_heartbeat_starts_at_the_open_time(self, conn):
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        assert conn.execute("SELECT heartbeat_us FROM run WHERE id=?",
                            (rid,)).fetchone()[0] == 1000

    def test_an_unknown_kind_is_refused(self, conn):
        """The vocabulary is S5's and it is closed. A typo'd kind that reached
        the table would be invisible to every query that filters on it."""
        with pytest.raises(ValueError, match="kind"):
            run_mod.open_run(conn, engagement_id=ENG, kind="brwose",
                             safety_profile="production", now_us=1000)


class TestAutoOpen:
    def test_current_run_opens_one_when_there_is_none(self, conn):
        rid = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                  safety_profile="production", now_us=1000)
        assert _status(conn, rid) == "running"

    def test_and_returns_the_same_one_while_it_is_live(self, conn):
        a = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production", now_us=1000)
        b = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production", now_us=2000)
        assert a == b

    def test_but_a_second_kind_gets_its_own_run(self, conn):
        """A crawl running while you browse is two runs, not one. Merging them
        would attribute crawler traffic to a human and vice versa, and the
        enforcement rules differ by exactly that distinction."""
        browse = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                     safety_profile="production", now_us=1000)
        crawl = run_mod.current_run(conn, engagement_id=ENG, kind="crawl",
                                    safety_profile="production", now_us=1000)
        assert browse != crawl

    def test_an_idle_run_is_closed_and_a_fresh_one_opened(self, conn):
        a = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production", now_us=1000)
        b = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production",
                                now_us=1000 + run_mod.IDLE_CLOSE_US + 1)
        assert b != a
        assert _status(conn, a) == "completed"

    def test_exactly_at_the_window_the_run_is_still_live(self, conn):
        """THE separating input, and the only one for `<=` versus `<`.

        Measured before this test existed: changing `<=` to `<` reddened
        NOTHING. Both other probes sit at +/-1 and agree under either operator,
        so the boundary looked tested from both sides and was tested from
        neither. The one input that tells them apart is exactly
        IDLE_CLOSE_US."""
        a = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production", now_us=1000)
        b = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production",
                                now_us=1000 + run_mod.IDLE_CLOSE_US)
        assert b == a

    def test_one_microsecond_inside_the_window_is_still_the_same_run(self, conn):
        """Inside the window, well away from the boundary."""
        a = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production", now_us=1000)
        b = run_mod.current_run(conn, engagement_id=ENG, kind="browse",
                                safety_profile="production",
                                now_us=1000 + run_mod.IDLE_CLOSE_US - 1)
        assert b == a


class TestStale:
    def test_a_run_left_running_past_the_window_resolves_to_error(self, conn):
        """NOT completed. This is the whole point of the heartbeat."""
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        reaped = run_mod.reap_stale(conn, now_us=1000 + HOUR)
        assert reaped == [rid]
        assert _status(conn, rid) == "error"

    def test_and_says_why_rather_than_leaving_an_empty_reason(self, conn):
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        run_mod.reap_stale(conn, now_us=1000 + HOUR)
        reason = conn.execute("SELECT stop_reason FROM run WHERE id=?",
                              (rid,)).fetchone()[0]
        assert reason and "heartbeat" in reason

    def test_a_live_run_is_not_reaped(self, conn):
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        run_mod.heartbeat(conn, run_id=rid, now_us=1000 + HOUR)
        assert run_mod.reap_stale(conn, now_us=1000 + HOUR + 1) == []
        assert _status(conn, rid) == "running"

    def test_an_already_closed_run_is_not_reopened_as_an_error(self, conn):
        """Separates 'stale' from 'old'. A completed run from last week is not
        a crash, and reaping it would rewrite history."""
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        run_mod.close_run(conn, run_id=rid, now_us=2000)
        assert run_mod.reap_stale(conn, now_us=1000 + HOUR) == []
        assert _status(conn, rid) == "completed"

    def test_a_run_idle_but_not_yet_stale_is_left_alone(self, conn):
        """The distinction the two windows exist for, and it had no test.

        An IDLE run is one nobody used; a STALE run is one whose process is
        gone. Reaping at the idle boundary would file every ordinary pause as a
        crash, and `reap_stale`'s window was free to collapse to IDLE_CLOSE_US
        with nothing red."""
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        just_idle = 1000 + run_mod.IDLE_CLOSE_US + 1
        assert run_mod.reap_stale(conn, now_us=just_idle) == []
        assert _status(conn, rid) == "running"

    def test_a_run_that_never_heartbeated_is_still_reaped(self, conn):
        """`NULL < x` is NULL and WHERE treats it as false, so a bare
        comparison never reaps a run that died before its first heartbeat --
        the exact case the mechanism is for."""
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        conn.execute("UPDATE run SET heartbeat_us=NULL WHERE id=?", (rid,))
        assert run_mod.reap_stale(conn, now_us=1000 + HOUR) == [rid]
        assert _status(conn, rid) == "error"


class TestDrops:
    def test_a_drop_is_counted(self, conn):
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        run_mod.count_drop(conn, run_id=rid, n=3)
        assert conn.execute("SELECT dropped_total FROM run WHERE id=?",
                            (rid,)).fetchone()[0] == 3

    def test_and_drops_accumulate_rather_than_overwrite(self, conn):
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        run_mod.count_drop(conn, run_id=rid, n=2)
        run_mod.count_drop(conn, run_id=rid, n=5)
        assert conn.execute("SELECT dropped_total FROM run WHERE id=?",
                            (rid,)).fetchone()[0] == 7

    def test_a_fresh_run_has_no_drops_rather_than_null(self, conn):
        """NULL would make `dropped_total > 0` quietly false for every run,
        which is the reading a report would take as 'no gaps'."""
        rid = run_mod.open_run(conn, engagement_id=ENG, kind="browse",
                               safety_profile="production", now_us=1000)
        assert conn.execute("SELECT dropped_total FROM run WHERE id=?",
                            (rid,)).fetchone()[0] == 0
