import io

from hx import session


class _FakeProc:
    """A launched process that never was. `pid` is real enough to be passed
    to a monkeypatched `not_loopback_only`, and `on_kill` lets a test prove
    teardown happened."""

    def __init__(self, on_kill=None):
        self.pid = 4242
        self.stdin = io.BytesIO()
        self._on_kill = on_kill

    def kill(self):
        if self._on_kill is not None:
            self._on_kill(self.pid)

    def wait(self, timeout=None):
        return 0


def test_the_launch_command_carries_every_required_property(monkeypatch, tmp_path):
    seen = {}

    def fake_popen(cmd, **kw):
        seen["cmd"], seen["kw"] = cmd, kw
        return _FakeProc()

    monkeypatch.setattr(session.subprocess, "Popen", fake_popen)
    session.launch_burp(tmp_path / "hx.sock", "e-1", tmp_path / "w",
                        sentinel=tmp_path / "HALTED", jar=tmp_path / "b.jar",
                        instance="capture")
    joined = " ".join(seen["cmd"])
    assert "-Dhx.halt_sentinel=" in joined, (
        "without the sentinel HxExtension returns early and never dials, so "
        "the handshake times out with nothing naming the cause")
    assert "-Dhx.crawler_port=" in joined, (
        "without it Source.forListenerPort answers OPERATOR for every request "
        "and S4's operator/agent split stops working silently")
    assert "-Dhx.instance=capture" in joined
    assert "--developer-extension-class-name=hx.HxExtension" in joined
    assert "--disable-auto-update" in joined


def test_the_crawler_port_is_the_one_burp_was_actually_given(monkeypatch, tmp_path):
    # Read back out of the config file, never from the argument, which may be
    # the 0 that means "choose one for me". A launch that instead interpolates
    # the raw crawler_port argument still passes every other assertion here,
    # so this pins the exact substring rather than "-Dhx.crawler_port=" alone.
    seen = {}

    def fake_popen(cmd, **kw):
        seen["cmd"] = cmd
        return _FakeProc()

    monkeypatch.setattr(session.subprocess, "Popen", fake_popen)

    # A distinctive non-zero port: the command must carry exactly this value,
    # not a substring match that "-Dhx.crawler_port=0" would also satisfy.
    session.launch_burp(tmp_path / "hx.sock", "e-1", tmp_path / "w",
                        sentinel=tmp_path / "HALTED", jar=tmp_path / "b.jar",
                        instance="capture", crawler_port=54321)
    joined = " ".join(seen["cmd"])
    assert "-Dhx.crawler_port=54321" in joined

    # crawler_port=0 means "choose one for me" -- the command must carry
    # whatever write_listener_config actually bound, never the literal 0.
    session.launch_burp(tmp_path / "hx.sock", "e-1", tmp_path / "w2",
                        sentinel=tmp_path / "HALTED", jar=tmp_path / "b.jar",
                        instance="capture", crawler_port=0)
    joined = " ".join(seen["cmd"])
    assert "-Dhx.crawler_port=0" not in joined, (
        "0 means choose one for me -- the raw argument must never reach the "
        "command line, or Source.forListenerPort answers OPERATOR for every "
        "request however many listeners are running")


def test_output_goes_to_a_file_not_a_pipe(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(session.subprocess, "Popen",
                        lambda cmd, **kw: (seen.update(kw), _FakeProc())[1])
    session.launch_burp(tmp_path / "hx.sock", "e-1", tmp_path / "w",
                        sentinel=tmp_path / "HALTED", jar=tmp_path / "b.jar",
                        instance="capture")
    assert seen["stdout"] is not session.subprocess.PIPE, (
        "an unread PIPE deadlocks once Burp fills the buffer")
    assert (tmp_path / "w" / "burp.log").exists()
