"""The launch command, built without launching anything.

NOTHING HERE MAY READ THE OPERATOR'S MACHINE. Only `Popen` was faked when
these tests were written, so `make_home` ran for real: every default `pytest`
run copied `~/.java/.userPrefs/burp/prefs.xml` and `~/.BurpSuite/sessions/`
into four `tmp_path` directories and symlinked the operator's `burpbrowser`.
They passed because this machine's `$HOME` had accepted the Burp licence, and
they went red with `HX_BURP_SEED_HOME=/nonexistent` -- which is to say on a CI
runner or a contributor's laptop, with a `SessionError` naming nothing about
the test.

Two facts of the environment are therefore supplied rather than borrowed. The
`seed` fixture is the home `make_home` copies, and it is passed in code rather
than through `$HX_BURP_SEED_HOME`, because the point is that a caller which
knows the answer says so. The `built_extension` fixture is the other one:
`launch_burp` calls `extension_problem()` before it launches, and
`extension/build/` is gitignored -- so on a fresh clone these tests failed on
a missing build product they are not about.
"""
import io

import pytest

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


@pytest.fixture
def seed(tmp_path):
    """A Burp home with an accepted licence, standing in for the operator's.

    The same shape `tests/test_session_home.py::seeded_home` builds, and the
    same reason: `make_home` refuses a seed that never accepted the EULA, and
    it copies `.java` wholesale and iterates `.BurpSuite`, so both have to be
    there or the copy dies half way through.
    """
    home = tmp_path / "seed"
    prefs = home / ".java" / ".userPrefs" / "burp"
    prefs.mkdir(parents=True)
    (prefs / "prefs.xml").write_bytes(
        b'<map><entry key="burp.eula" value="true"/></map>')
    (home / ".BurpSuite").mkdir()
    (home / ".BurpSuite" / "UserConfigCommunity.json").write_text("{}")
    return home


@pytest.fixture
def built_extension(tmp_path, monkeypatch):
    """A bridge jar newer than its sources, so `extension_problem()` passes.

    Pointed at `tmp_path` rather than stubbed out: the pre-flight still runs
    for real, it just stops depending on `extension/build/hx-bridge.jar`,
    which is gitignored and absent on any machine that has not run build.sh.
    An empty source tree makes `_newest_source_mtime()` 0.0, which is younger
    than anything.
    """
    jar = tmp_path / "ext" / "build" / "hx-bridge.jar"
    jar.parent.mkdir(parents=True)
    jar.write_bytes(b"not really a jar; nothing here launches a JVM")
    src = tmp_path / "ext" / "src"
    src.mkdir(parents=True)
    monkeypatch.setattr(session, "EXT_JAR", jar)
    monkeypatch.setattr(session, "EXT_SRC", src)
    return jar


def test_the_launch_command_carries_every_required_property(
        monkeypatch, tmp_path, seed, built_extension):
    seen = {}

    def fake_popen(cmd, **kw):
        seen["cmd"], seen["kw"] = cmd, kw
        return _FakeProc()

    monkeypatch.setattr(session.subprocess, "Popen", fake_popen)
    session.launch_burp(tmp_path / "hx.sock", "e-1", tmp_path / "w",
                        sentinel=tmp_path / "HALTED", jar=tmp_path / "b.jar",
                        instance="capture", seed=seed)
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


def test_the_crawler_port_is_the_one_burp_was_actually_given(
        monkeypatch, tmp_path, seed, built_extension):
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
                        instance="capture", crawler_port=54321, seed=seed)
    joined = " ".join(seen["cmd"])
    assert "-Dhx.crawler_port=54321" in joined

    # crawler_port=0 means "choose one for me" -- the command must carry
    # whatever write_listener_config actually bound, never the literal 0.
    session.launch_burp(tmp_path / "hx.sock", "e-1", tmp_path / "w2",
                        sentinel=tmp_path / "HALTED", jar=tmp_path / "b.jar",
                        instance="capture", crawler_port=0, seed=seed)
    joined = " ".join(seen["cmd"])
    assert "-Dhx.crawler_port=0" not in joined, (
        "0 means choose one for me -- the raw argument must never reach the "
        "command line, or Source.forListenerPort answers OPERATOR for every "
        "request however many listeners are running")


def test_output_goes_to_a_file_not_a_pipe(
        monkeypatch, tmp_path, seed, built_extension):
    seen = {}
    monkeypatch.setattr(session.subprocess, "Popen",
                        lambda cmd, **kw: (seen.update(kw), _FakeProc())[1])
    session.launch_burp(tmp_path / "hx.sock", "e-1", tmp_path / "w",
                        sentinel=tmp_path / "HALTED", jar=tmp_path / "b.jar",
                        instance="capture", seed=seed)
    assert seen["stdout"] is not session.subprocess.PIPE, (
        "an unread PIPE deadlocks once Burp fills the buffer")
    assert (tmp_path / "w" / "burp.log").exists()


def test_the_seed_is_the_one_the_caller_named_not_the_operators(
        monkeypatch, tmp_path, seed, built_extension):
    """The regression this whole fixture pair exists for.

    `launch_burp` must copy the home it was HANDED. Proved by making
    `seed_home()` -- the default -- explode: a launch that still consulted it
    would raise instead of building a home, and the copy that lands in the
    workdir could then only have come from `seed`.
    """
    def never(*_a, **_k):
        raise AssertionError(
            "launch_burp read the operator's Burp home despite being handed "
            "a seed; every default pytest run would copy ~/.BurpSuite again")

    monkeypatch.setattr(session, "seed_home", never)
    monkeypatch.setattr(session.subprocess, "Popen",
                        lambda cmd, **kw: _FakeProc())
    session.launch_burp(tmp_path / "hx.sock", "e-1", tmp_path / "w",
                        sentinel=tmp_path / "HALTED", jar=tmp_path / "b.jar",
                        instance="capture", seed=seed)
    copied = tmp_path / "w" / "burphome" / ".BurpSuite" / "UserConfigCommunity.json"
    assert copied.exists(), "the named seed's contents are what should be copied"
