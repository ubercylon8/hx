"""The two extractions Task 1 makes, and the behaviour they must not move."""
from __future__ import annotations

from hx import run as run_mod


def test_a_completed_run_is_never_stale():
    """Staleness is a property of `running` runs only. A completed run's
    heartbeat stopped because the run ended, which is not a dead harness."""
    assert run_mod.is_stale("completed", 0, 0, before_us=10_000) is False


def test_a_running_run_with_a_fresh_heartbeat_is_not_stale():
    assert run_mod.is_stale("running", 20_000, 0, before_us=10_000) is False


def test_a_running_run_with_an_old_heartbeat_is_stale():
    assert run_mod.is_stale("running", 5_000, 0, before_us=10_000) is True


def test_a_run_that_never_heartbeated_falls_back_to_started_us():
    """The case `reap_stale`'s COALESCE exists for: `heartbeat_us` is
    NULLable, and a run that died BEFORE its first heartbeat is precisely
    what the mechanism is for. In SQL `NULL < x` is NULL and WHERE treats
    that as false, so such a run would never be reaped."""
    assert run_mod.is_stale("running", None, 5_000, before_us=10_000) is True
    assert run_mod.is_stale("running", None, 20_000, before_us=10_000) is False


def test_the_window_is_twice_the_idle_close():
    """Deliberately WIDER than IDLE_CLOSE_US: an idle run is one nobody used,
    a stale one is a run whose process is gone. Reaping at the idle boundary
    would file every ordinary pause as a crash."""
    assert run_mod.stale_before_us(now_us=1_000_000_000) == (
        1_000_000_000 - run_mod.IDLE_CLOSE_US * 2)
    assert run_mod.stale_before_us(now_us=500, stale_after_us=100) == 400
