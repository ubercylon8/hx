"""Burp's own bundled Chromium, launched sandboxed through our own proxy.

hx NEVER BUNDLES BURP and does not bundle a browser either. Chromium is
located inside the operator's own Burp installation, where Burp downloads
it on first use of the Proxy tab's browser. If it is not there, that is an
ordinary state with an ordinary fix, and this module says so rather than
raising a FileNotFoundError from somewhere in the middle of a crawl.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from hx.crawl import cdp

#: Where Burp puts the browser it downloads.
BURP_HOME = Path.home() / ".BurpSuite"


class BrowserUnavailable(Exception):
    """No usable Chromium, or one that will not start under a sandbox."""


def _version_key(name: str) -> tuple[int, ...]:
    """`150.0.7871.186` -> (150, 0, 7871, 186).

    Numeric, because lexicographic ordering puts "9.0.0.0" after
    "150.0.7871.186" and would silently pick a browser years out of date.
    """
    parts = []
    for piece in name.split("."):
        parts.append(int(piece) if piece.isdigit() else -1)
    return tuple(parts)


def find_chromium(burp_home: Path | None = None) -> Path:
    """The newest `burpbrowser/<version>/chrome` under `burp_home`."""
    home = Path(burp_home) if burp_home is not None else BURP_HOME
    root = home / "burpbrowser"
    candidates = []
    if root.is_dir():
        for child in root.iterdir():
            exe = child / "chrome"
            if child.is_dir() and exe.is_file() and os.access(exe, os.X_OK):
                candidates.append(child)
    if not candidates:
        raise BrowserUnavailable(
            f"no bundled Chromium under {root}. Burp downloads it the first "
            "time you open its own browser (Proxy -> Intercept -> Open "
            "browser); do that once and re-run. hx does not ship a browser.")
    newest = max(candidates, key=lambda d: _version_key(d.name))
    return newest / "chrome"


def launch_argv(chrome: Path, *, proxy_port: int,
                 user_data_dir: Path) -> list[str]:
    """Exactly what we ask Chromium for, as data so it can be reviewed.

    THE SECOND FLAG IS THE ONE THAT MATTERS. Measured 2026-09-02: with
    `--proxy-server` alone and a loopback target, Chromium sent ZERO
    connections to the proxy and connected directly -- around the crawler
    listener, around ProxyGate, around every S4 enforcement point. Chrome
    bypasses proxies for loopback by default. Every target in this repo is
    loopback by mandate, so a crawler missing this flag passes every test we
    are allowed to write.

    NO `--no-sandbox`. Verified the same day that Chromium starts sandboxed
    here through unprivileged user namespaces, so there is nothing to trade.

    `--ignore-certificate-errors` is deliberate and its cost is written down
    in the spec: every certificate this browser can see is one Burp minted,
    because the two flags above leave it no other route. The crawler
    therefore cannot observe TLS problems on the target -- Burp still can,
    and does. Pinning to Burp's CA SPKI is the better version and is
    deferred, because hx does not parse certificates.
    """
    return [
        str(chrome),
        "--headless",
        f"--proxy-server=127.0.0.1:{proxy_port}",
        "--proxy-bypass-list=<-loopback>",
        "--ignore-certificate-errors",
        "--remote-debugging-pipe",
        f"--user-data-dir={user_data_dir}",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-client-side-phishing-detection",
        "--disable-sync",
        "--metrics-recording-only",
        "about:blank",
    ]


class Browser:
    """A launched Chromium, its CDP connection, and its one page session.

    A context manager, because a leaked Chromium survives the crawl, holds a
    private profile directory open, and keeps a proxy connection the
    extension is accounting for.

    `--remote-debugging-pipe` gives a BROWSER-level CDP session: the Page,
    Network, DOM and Runtime domains do not exist on it (Ruling 9, measured
    2026-09-02 -- `Page.enable` came back "wasn't found" without this).
    `__enter__` therefore creates a page target and attaches to it with
    `flatten: True`, exposing the resulting `session_id` for callers (Task 5's
    `page.visit`) to pass on every domain call. The attach lives here, on the
    browser's lifetime, rather than per page: re-attaching per page would be
    both wasteful and racy.
    """

    def __init__(self, *, proxy_port: int, burp_home: Path | None = None,
                 chrome: Path | None = None, handshake_timeout: float = 20.0,
                 stderr_timeout: float = 10.0) -> None:
        self._chrome = Path(chrome) if chrome else find_chromium(burp_home)
        self._proxy_port = proxy_port
        # `ignore_cleanup_errors` because Chromium outlives its own main
        # process: zygote and renderer children can still be flushing the
        # profile when `close()` removes it, and the removal then raises
        # `OSError: [Errno 39] Directory not empty`. MEASURED 2026-09-04 --
        # it appeared only once a crawl got far enough to write a real
        # profile, so the shorter crawls before it never hit it.
        #
        # A scratch directory that will not delete is a few hundred kilobytes
        # in /tmp. Failing the whole crawl over it would discard everything
        # the run captured, which is the worse of the two outcomes by a wide
        # margin.
        self._tmp = tempfile.TemporaryDirectory(
            prefix="hx-crawl-profile-", ignore_cleanup_errors=True)
        self.proc: subprocess.Popen | None = None
        self.conn: cdp.Connection | None = None
        self.session_id: str | None = None
        # Testability seams: production callers never set these, so the
        # defaults are the timeouts measured for a real Chromium handshake
        # (Ruling 9) and for reading a killed child's stderr (Ruling 6).
        # Tests that must stay fast without a real browser pass shorter
        # values through the constructor rather than mocking `cdp.Connection`.
        self._handshake_timeout = handshake_timeout
        self._stderr_timeout = stderr_timeout

    def __enter__(self) -> Browser:
        # `open_fds` is every raw descriptor this method still owns and must
        # close on any path that is not a successful return. Two things hand
        # descriptors off to something else that will close them instead: a
        # successful `Popen()` (the child's dup2'd copies of fds 3/4 become
        # the CHILD's to close on exit, so the parent's `to_child_r` and
        # `from_child_w` are closed right here) and a successful
        # `cdp.Connection(...)` (which owns `from_child_r`/`to_child_w` from
        # then on, via `Connection.close()`). Each handoff removes its fds
        # from this set so a failure after it does not double-close them --
        # and a failure BEFORE either handoff (even the first `os.pipe()`
        # succeeding but the second failing) still finds every fd it made in
        # the set and closes it exactly once.
        open_fds: set[int] = set()
        try:
            to_child_r, to_child_w = os.pipe()
            open_fds.update((to_child_r, to_child_w))
            from_child_r, from_child_w = os.pipe()
            open_fds.update((from_child_r, from_child_w))

            def fixup() -> None:
                # dup2 ONTO 3 and 4, and `pass_fds=(3, 4)` below is not
                # optional. subprocess closes descriptors outside pass_fds
                # AFTER preexec_fn runs, so without it these are closed
                # before exec and Chromium answers "Remote debugging pipe
                # file descriptors are not open." Measured 2026-09-02, on
                # the first attempt at this.
                os.dup2(to_child_r, 3)
                os.dup2(from_child_w, 4)

            argv = launch_argv(self._chrome, proxy_port=self._proxy_port,
                                user_data_dir=Path(self._tmp.name))
            self.proc = subprocess.Popen(
                argv, preexec_fn=fixup, pass_fds=(3, 4), close_fds=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            os.close(to_child_r)
            open_fds.discard(to_child_r)
            os.close(from_child_w)
            open_fds.discard(from_child_w)
            self.conn = cdp.Connection(read_fd=from_child_r, write_fd=to_child_w)
            open_fds.discard(from_child_r)
            open_fds.discard(to_child_w)

            self.conn.call("Browser.getVersion", timeout=self._handshake_timeout)
            target_id = self.conn.call(
                "Target.createTarget", {"url": "about:blank"},
                timeout=self._handshake_timeout)["targetId"]
            self.session_id = self.conn.call(
                "Target.attachToTarget",
                {"targetId": target_id, "flatten": True},
                timeout=self._handshake_timeout)["sessionId"]
        except cdp.CdpError as e:
            detail = self._kill_and_read_stderr()
            self.close()
            raise BrowserUnavailable(
                "Chromium started but did not answer CDP. If the message "
                "below mentions the sandbox, hx will not disable it: "
                f"{detail}") from e
        except BaseException:
            # BaseException, not Exception: a KeyboardInterrupt between
            # `Popen()` and the handshake must not leak a running Chromium
            # either. Whatever wasn't handed off above is still in
            # `open_fds`; whatever WAS handed off is closed by `close()`
            # via `self.proc`/`self.conn`, which are `None` if their
            # construction never completed.
            for fd in open_fds:
                try:
                    os.close(fd)
                except OSError:
                    pass
            self.close()
            raise
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _kill_and_read_stderr(self) -> str:
        """Chromium's own words about why it would not start.

        KILL FIRST, and that ordering is the whole method.
        `proc.stderr.read()` blocks until EOF, and a Chromium that launched
        but never answered CDP is still running -- so reading before killing
        hangs the error path forever. MEASURED 2026-09-02: `read()` had not
        returned after 2s against a live child.
        """
        if self.proc is None:
            return ""
        self.proc.kill()
        try:
            _, err = self.proc.communicate(timeout=self._stderr_timeout)
        except (subprocess.TimeoutExpired, ValueError, OSError):
            return ""
        return (err or b"").decode("utf-8", "replace")[:400]

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()
            self.conn = None
        if self.proc is not None:
            self.proc.kill()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            self.proc = None
        self._tmp.cleanup()
