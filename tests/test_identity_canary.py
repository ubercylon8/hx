from __future__ import annotations

from hx import config, identity
from hx.checks import probe


class _Sender:
    """A ProbeSender-shaped double. `bodies` is answered in order."""

    def __init__(self, *bodies: bytes, status: int = 200) -> None:
        self._bodies = list(bodies)
        self._status = status
        self.paths: list[str] = []

    def get(self, path, *, headers=None, timeout=30.0):
        self.paths.append(path)
        body = self._bodies.pop(0) if self._bodies else b""
        return probe.ProbeResponse(status=self._status, head=b"HTTP/1.1 200 OK\r\n",
                                   body=body, outcome="ok")


LIVE = config.Liveness(path="/account", expect_body="Sign out",
                       expect_absent="Sign in", every_n_probes=3)


def test_the_signature_present_is_a_pass():
    assert identity.canary(LIVE, _Sender(b"<a>Sign out</a>")) is True


def test_the_signature_absent_is_a_failure():
    assert identity.canary(LIVE, _Sender(b"<h1>Please Sign in</h1>")) is False


def test_a_200_login_page_fails_even_though_the_status_is_fine():
    # THE CASE THE WHOLE DESIGN TURNS ON. A canary keyed on status would pass
    # here, stamp the identity `proven`, and Task 8 would retire real findings
    # on the strength of it.
    page = b"<html><body><h1>Sign in</h1></body></html>"
    assert identity.canary(LIVE, _Sender(page, status=200)) is False


def test_expect_absent_vetoes_a_page_that_contains_both():
    both = b"<a>Sign out</a><form>Sign in</form>"
    assert identity.canary(LIVE, _Sender(both)) is False


def test_a_non_2xx_fails_whatever_the_body_says():
    s = _Sender(b"Sign out", status=500)
    assert identity.canary(LIVE, s) is False


def test_a_refusal_is_a_failure_not_an_exception():
    class Refusing:
        def get(self, *a, **k):
            raise probe.ProbeRefused("rate_limited")
    assert identity.canary(LIVE, Refusing()) is False


# ---- the window ---------------------------------------------------------


def test_a_canary_is_due_every_n_probes():
    w = identity.IdentityWindow(due_every=3)
    w.open(passed=True)
    assert [w.note_probe() for _ in range(4)] == [False, False, True, False]


def test_a_window_closed_by_a_passing_canary_is_proven():
    w = identity.IdentityWindow(due_every=3)
    w.open(passed=True)
    w.note_probe()
    w.close(passed=True)
    assert w.state_for_run() == "proven"


def test_a_window_whose_closing_canary_failed_is_assumed_not_proven():
    # The session may have died at any point inside it, so nothing issued in
    # the window is proof of anything. Under-claim rather than over-claim.
    w = identity.IdentityWindow(due_every=3)
    w.open(passed=True)
    w.note_probe()
    w.close(passed=False)
    assert w.state_for_run() == "assumed"


def test_a_window_that_never_opened_cleanly_is_dead():
    w = identity.IdentityWindow(due_every=3)
    w.open(passed=False)
    assert w.state_for_run() == "dead"


def test_one_failed_canary_downgrades_the_whole_run_not_just_its_window():
    # `state_for_run` is what Task 8's retirement gate reads, and it is about
    # the RUN. A run with any unproven window may retire nothing: the finding
    # that would be retired could live on a surface probed inside it.
    w = identity.IdentityWindow(due_every=2)
    w.open(passed=True)
    w.note_probe()
    w.note_probe()
    w.close(passed=False)
    w.open(passed=True)
    w.close(passed=True)
    assert w.state_for_run() == "assumed"
