"""`hx.crawl.browser`: what we ask Chromium for, and where we find it.

MOSTLY WITHOUT LAUNCHING ONE. The argv is a list of strings and the
discovery is a directory walk; both are testable as data, and testing them
as data is what makes the flags reviewable. The two tests that drive a
subprocess use a tiny fake "chrome" script, never real Chromium -- the one
test that starts a real Chromium lives in the integration suite (Task 9).
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from hx.crawl import browser


def _fake_burp_home(tmp_path: Path, *versions: str) -> Path:
    for v in versions:
        d = tmp_path / "burpbrowser" / v
        d.mkdir(parents=True)
        (d / "chrome").write_text("#!/bin/true\n")
        (d / "chrome").chmod(0o755)
    return tmp_path


def test_the_proxy_bypass_flag_is_present():
    """THE LOAD-BEARING FLAG. Measured 2026-09-02: without it Chrome sent
    ZERO connections to the proxy for a loopback target and went direct,
    around ProxyGate and every S4 enforcement point.

    MUTATION: delete `--proxy-bypass-list=<-loopback>` from `launch_argv`.
    This test must go red. Task 9's integration test must ALSO go red -- a
    unit test on argv proves we ask for it, not that it works.
    """
    argv = browser.launch_argv(Path("/x/chrome"), proxy_port=8080,
                                user_data_dir=Path("/tmp/p"))
    assert "--proxy-bypass-list=<-loopback>" in argv


def test_the_proxy_is_the_only_route_out():
    argv = browser.launch_argv(Path("/x/chrome"), proxy_port=9999,
                                user_data_dir=Path("/tmp/p"))
    assert "--proxy-server=127.0.0.1:9999" in argv


def test_the_sandbox_is_never_disabled():
    """MUTATION: add `--no-sandbox` to `launch_argv`. Must go red.

    A security tool renders hostile pages. Verified 2026-09-02 that
    Chromium starts sandboxed on this platform via unprivileged user
    namespaces, so there is nothing to trade off.
    """
    argv = browser.launch_argv(Path("/x/chrome"), proxy_port=1,
                                user_data_dir=Path("/tmp/p"))
    assert "--no-sandbox" not in argv
    assert not any("disable-setuid-sandbox" in a for a in argv)


def test_the_profile_is_private_to_the_run():
    """A crawl never touches a real browser profile -- the rule the private
    Burp home already follows.

    MUTATION: drop `--user-data-dir` from the argv. Must go red.
    """
    argv = browser.launch_argv(Path("/x/chrome"), proxy_port=1,
                                user_data_dir=Path("/tmp/private-profile"))
    assert "--user-data-dir=/tmp/private-profile" in argv


def test_remote_debugging_is_a_pipe_and_never_a_port():
    """MUTATION: replace with `--remote-debugging-port=0`. Must go red.

    A port is a socket, a socket needs a client in `src/hx`, and that is the
    thing `pyproject.toml`'s httpx2 note objects to.
    """
    argv = browser.launch_argv(Path("/x/chrome"), proxy_port=1,
                                user_data_dir=Path("/tmp/p"))
    assert "--remote-debugging-pipe" in argv
    assert not any(a.startswith("--remote-debugging-port") for a in argv)


def test_the_newest_bundled_chromium_wins(tmp_path):
    home = _fake_burp_home(tmp_path, "9.0.1.2", "150.0.7871.186", "31.0.0.0")
    assert browser.find_chromium(home).parent.name == "150.0.7871.186"


def test_versions_are_compared_numerically_and_not_as_strings(tmp_path):
    """`"9" > "150"` lexicographically. MUTATION: sort with `sorted(dirs)`.
    Must go red -- and the crawler would silently drive an ancient browser.
    """
    home = _fake_burp_home(tmp_path, "9.0.0.0", "150.0.7871.186")
    assert browser.find_chromium(home).parent.name == "150.0.7871.186"


def test_a_missing_browser_is_a_named_refusal_not_a_crash(tmp_path):
    """Burp downloads its browser on first use, so 'not there yet' is an
    ordinary state an operator must be told how to fix."""
    with pytest.raises(browser.BrowserUnavailable, match="burpbrowser"):
        browser.find_chromium(tmp_path)


def test_session_id_is_none_before_the_browser_is_entered():
    """Ruling 9: `Browser` exposes `.session_id` so Task 5/6 can read it. It
    starts `None` -- there is no page session before a Chromium exists."""
    b = browser.Browser(proxy_port=1, chrome=Path("/x/chrome"))
    assert b.session_id is None


def test_a_construction_failure_leaves_no_fds_process_or_profile_dir(
        tmp_path, monkeypatch):
    """`__enter__` opens two pipes, then calls `Popen()` and
    `cdp.Connection()` -- both of which can raise something that is not a
    `cdp.CdpError` (a bad exec, fd exhaustion, a `Connection()` construction
    failure). Only the CDP-call block was ever guarded; an exception from
    `Popen()` or `Connection()` used to propagate out of `__enter__`
    uncaught. Python never calls `__exit__` on a context manager whose
    `__enter__` didn't return, so `close()` never ran: a leaked Chromium (if
    `Popen()` had succeeded) plus the profile dir plus whichever pipe fds
    hadn't yet been handed off.

    This fixture makes `Popen()` itself fail: `chrome` exists but is not
    executable, so `Popen()` raises `PermissionError` while trying to exec
    it -- a plain `OSError`, not `cdp.CdpError`, so only a guard around the
    WHOLE construction (not just the CDP calls) can catch it. At the moment
    of failure all four pipe fds `__enter__` opened are still unhanded-off
    (Popen never returned, so the parent-side `os.close()` calls right
    after it never ran either) -- which is exactly the case that exercises
    the fix, not a degenerate one where there was nothing left to leak.

    MUTATION: remove the `try`/`except BaseException` wrapping the whole of
    `__enter__` (i.e. revert to guarding only the CDP-call block, as the
    task brief originally had it). Must go red: the four fds this test
    tracks stay open (`os.fstat` on them no longer raises), and the profile
    directory survives.

    `os.pipe` is spied on rather than guessed at, so the test checks the
    OWN four fds `__enter__` made, not a coincidence. `b` is kept alive for
    the whole test (never `del`eted, never let go out of scope before the
    assertions run) specifically so `TemporaryDirectory`'s GC finalizer
    cannot be the thing that removes the profile directory -- a finalizer
    only runs once nothing still references the `TemporaryDirectory`, and a
    live `b` holds one via `b._tmp` throughout. If the directory is gone,
    `close()` removed it, not garbage collection.
    """
    chrome = tmp_path / "not-executable-chrome"
    chrome.write_text("#!/bin/true\n")
    # Deliberately NOT chmod'd +x.

    created_fds: list[int] = []
    real_pipe = os.pipe

    def spy_pipe():
        pair = real_pipe()
        created_fds.extend(pair)
        return pair

    monkeypatch.setattr(os, "pipe", spy_pipe)

    b = browser.Browser(proxy_port=1, chrome=chrome)
    with pytest.raises(PermissionError):
        b.__enter__()

    # `__enter__`'s own two `os.pipe()` calls happen first, before
    # `Popen()` -- which then opens an fd pair of its OWN internally, to
    # report a failed exec back to the parent. That third pair is
    # `subprocess`'s to close, not ours; only the first four are `__enter__`'s.
    assert len(created_fds) >= 4, "fixture assumption: __enter__ opens two pipes"
    our_fds = created_fds[:4]
    for fd in our_fds:
        with pytest.raises(OSError):
            os.fstat(fd)  # closed fds fail fstat with EBADF

    assert b.proc is None
    assert b.conn is None
    assert not Path(b._tmp.name).exists(), \
        "profile dir survived a failed __enter__"


# --- fixtures for the two tests that drive a subprocess --------------------


def _fake_chrome_script(tmp_path: Path, body: str) -> Path:
    """A tiny shebang script standing in for Chromium on fds 3/4.

    Popen execs `argv[0]` directly (no shell), so this must be a real
    executable file, not a `python -c ...` invocation -- `launch_argv`
    appends Chromium-shaped flags after `argv[0]` that a bare interpreter
    invocation could not parse. A shebang script ignores them like any CLI
    tool ignores flags it doesn't ask for.
    """
    script = tmp_path / "fake-chrome"
    script.write_text(f"#!{sys.executable}\n{body}")
    script.chmod(0o755)
    return script


_CDP_PEER_BODY = """
import json, os

def send(msg):
    os.write(4, json.dumps(msg).encode() + b"\\0")

buf = b""
while True:
    chunk = os.read(3, 65536)
    if not chunk:
        break
    buf += chunk
    while b"\\0" in buf:
        raw, buf = buf.split(b"\\0", 1)
        if not raw:
            continue
        msg = json.loads(raw)
        method = msg.get("method")
        if method == "Browser.getVersion":
            send({"id": msg["id"], "result": {"product": "fake/1.0"}})
        elif method == "Target.createTarget":
            send({"id": msg["id"], "result": {"targetId": "target-1"}})
        elif method == "Target.attachToTarget":
            if msg.get("params", {}).get("flatten") is True:
                send({"id": msg["id"],
                      "result": {"sessionId": "session-abc"}})
            else:
                send({"id": msg["id"],
                      "error": {"code": -1, "message": "flatten required"}})
        else:
            send({"id": msg["id"], "result": {}})
"""


def test_entering_attaches_a_flattened_page_session(tmp_path):
    """Ruling 9, measured 2026-09-02 against real Chromium: a
    `--remote-debugging-pipe` connection is BROWSER-level. `Page`, `Network`,
    `DOM` and `Runtime` don't exist on it (`Page.enable: 'Page.enable' wasn't
    found`). `__enter__` must create a page target and attach with
    `flatten: True`, and store the resulting session id.

    MUTATION 1: remove the `Target.createTarget` / `Target.attachToTarget`
    calls from `__enter__` (revert to the pre-Ruling-9 handshake). Must go
    red -- `session_id` stays `None` and the assertion below fails.

    MUTATION 2: drop `"flatten": True` from the `Target.attachToTarget`
    params. Must go red -- this fixture's fake peer refuses to hand out a
    session id without it, so `__enter__` raises `BrowserUnavailable`
    instead of returning.
    """
    chrome = _fake_chrome_script(tmp_path, _CDP_PEER_BODY)
    with browser.Browser(proxy_port=1, chrome=chrome) as b:
        assert b.session_id == "session-abc"


def test_a_browser_that_never_answers_cdp_fails_instead_of_hanging(tmp_path):
    """Ruling 6, and it overrides the brief. The brief's error path read
    `proc.stderr.read()` BEFORE killing the child; `read()` blocks until
    EOF, and a Chromium that launched but never answers CDP is still alive,
    so the crawler would hang forever inside the very handler that exists to
    report a refused sandbox. MEASURED 2026-09-02: `read()` had not returned
    after 2s against a live child.

    MUTATION: in `_kill_and_read_stderr`, move `self.proc.kill()` to AFTER
    `self.proc.communicate(...)`. Must go red: `communicate()` then waits
    for the still-running fake "chromium" to exit on its own, which it never
    does until it hits ITS OWN `communicate(timeout=self._stderr_timeout)`
    ceiling -- blowing the wall-clock bound asserted below. This is the
    "goes red by timing out, not by asserting" case the ruling calls for:
    `pytest-timeout` is not a dependency, so the bound is measured with
    `time.monotonic()` instead of a marker.

    Uses `handshake_timeout=` / `stderr_timeout=` -- testability seams added
    to `Browser.__init__` for exactly this test, documented in the task
    report. Production code never sets them; the defaults are the timeouts
    Ruling 6 and Ruling 9 specify (10s / 20s).
    """
    chrome = _fake_chrome_script(
        tmp_path,
        "import sys, time\n"
        "sys.stderr.write('fake refusal: sandbox message\\n')\n"
        "sys.stderr.flush()\n"
        "time.sleep(60)\n",
    )
    start = time.monotonic()
    with pytest.raises(browser.BrowserUnavailable, match="sandbox"):
        with browser.Browser(proxy_port=1, chrome=chrome,
                              handshake_timeout=0.3, stderr_timeout=3.0):
            pass
    elapsed = time.monotonic() - start
    # Correct code: kill first, so `communicate()` on an already-dead child
    # returns near-instantly -- measured ~0.3s (just handshake_timeout, the
    # CdpTimeout on the browser-level handshake). Under the mutation,
    # `communicate()` runs BEFORE the kill and must wait out the full
    # `stderr_timeout` against a child that is still very much alive --
    # measured ~3.3s. 2s cleanly separates the two without being flaky.
    assert elapsed < 2.0, f"took {elapsed:.2f}s -- the error path hung"
