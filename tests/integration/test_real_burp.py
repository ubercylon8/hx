import hashlib

import pytest

from hx import halt as halt_mod
from hx.bridge import server
from hx.store import db as db_mod
from hx.store.paths import secure_mkdir
from tests.integration import burp_fixture as bf

pytestmark = pytest.mark.integration


def _operator_halt(workdir, engagement_id):
    """`BridgeServer` requires one -- the same call HxExtension makes about
    `-Dhx.halt_sentinel`, for the same field. A harness with no engagement of
    its own supplies a sentinel in a directory of its own, which is what this
    builds.

    NOTE for the integration task, from measuring these two against the real
    container on 2026-08-23. Both fail today, for two separate reasons, and
    both failures predate this function -- the pristine tree fails the same
    way:

      1. Burp 2026.7.3 dies during startup under this machine's JRE 26 with
         `java.lang.Error: no ComponentUI class for: burp.Zc7w`, before the
         extension is loaded at all. That is what the current failure is.
      2. Behind it, `bf.launch_burp` does not pass `-Dhx.halt_sentinel`, and
         HxExtension.initialize() refuses to come up without it ("extension
         idle"). Even with a working JVM the handshake could not complete
         until the fixture hands the JVM `oh.sentinel_path`.

    Neither is this fix round's to repair. This function exists so the Python
    half is already correct when they are.
    """
    root = workdir / "engagement"
    secure_mkdir(root)
    conn = db_mod.connect(root / "hx.db")
    db_mod.init_schema(conn)
    conn.execute("INSERT INTO engagement(id, name, client, created_us, status)"
                 " VALUES(?,'Integration','Integration',1,'active')",
                 (engagement_id,))
    return halt_mod.OperatorHalt(root, conn)


@pytest.mark.skipif(not bf.burp_available(),
                    reason=f"missing: {', '.join(bf.missing())}")
def test_real_burp_dials_in_and_handshakes(tmp_path):
    """The whole point of this plan, proved against the real container.

    Fakes prove the logic; only this proves Burp actually loads the extension
    and that the socket handshake works end to end.
    """
    srv = server.BridgeServer(
        tmp_path / "hx.sock", engagement_id="e-integration",
        operator_halt=_operator_halt(tmp_path, "e-integration"))
    srv.start()
    proc = None
    try:
        proc = bf.launch_burp(srv.socket_path, "e-integration", tmp_path)

        assert bf.wait_for(lambda: srv.state == "connected"), \
            "Burp never completed the hello handshake"

        assert srv.hello["engagement_id"] == "e-integration"
        assert srv.hello["instance_id"] == "integration"
        assert "2026" in srv.hello["burp_version"], srv.hello
        # Ties the handshake to the JVM this test launched. peer_pid comes
        # from SO_PEERCRED -- the kernel fills it in and a peer cannot forge
        # it. The assertion this replaced, `peer_uid is not None`, could not
        # fail: _serve() sets peer_uid before the read loop and returns on a
        # uid mismatch, so state == "connected" already implies it.
        assert srv.peer_pid == proc.pid
        # The same number, self-reported in the hello frame. Weaker evidence
        # than the credential above, and worth checking separately: it is
        # what an operator sees, and it agreeing with the kernel is what
        # makes it trustworthy.
        assert srv.hello["pid"] == proc.pid

        pairs = {"scope.include": ["https://app.example.test/*"],
                 "limit.rate_rps": ["5"]}
        epoch = srv.configure(
            pairs,
            scope_sha256=hashlib.sha256(b"x").hexdigest(),
            profile="production",
        )
        assert epoch == 1
        assert srv.state == "configured"
    finally:
        if proc:
            proc.kill()
            proc.wait(timeout=15)
        srv.stop()


@pytest.mark.skipif(not bf.burp_available(),
                    reason=f"missing: {', '.join(bf.missing())}")
def test_burp_restart_returns_the_bridge_to_deny_all(tmp_path):
    """A Burp restart is a reconnect, not an outage -- and the reconnected
    extension knows nothing, because extensionData does not survive.

    Both halves are here. Killing Burp proves the bridge returns to DENY-ALL;
    only the second Burp dialling the same live BridgeServer proves the
    "reconnect, not an outage" half, which is this plan's headline claim and
    was otherwise exercised against fakes alone.
    """
    srv = server.BridgeServer(
        tmp_path / "hx.sock", engagement_id="e-restart",
        operator_halt=_operator_halt(tmp_path, "e-restart"))
    srv.start()
    proc = proc2 = None
    try:
        proc = bf.launch_burp(srv.socket_path, "e-restart", tmp_path / "first")
        assert bf.wait_for(lambda: srv.state == "connected")
        srv.configure({"scope.include": ["https://a/*"]},
                      scope_sha256="abc", profile="production")
        assert srv.state == "configured"

        proc.kill()
        proc.wait(timeout=15)
        assert bf.wait_for(lambda: srv.state == "waiting", timeout=30), \
            "dropped connection must return the bridge to DENY-ALL"
        assert srv.config_epoch == 0

        # The restart. Same socket, same server object, never stopped.
        proc2 = bf.launch_burp(srv.socket_path, "e-restart", tmp_path / "second")
        assert bf.wait_for(lambda: srv.state == "connected"), \
            "a restarted Burp must reconnect to the still-listening bridge"
        assert srv.peer_pid == proc2.pid, "the bridge is talking to the old JVM"
        # Still DENY-ALL: the reconnected extension carries nothing over,
        # because extensionData does not survive a Burp restart.
        assert srv.config_epoch == 0

        epoch = srv.configure({"scope.include": ["https://b/*"]},
                              scope_sha256="def", profile="production")
        assert epoch == 1, "a fresh extension numbers its first scope 1"
        assert srv.state == "configured"
    finally:
        # The first kill is inside the try for a reason -- it IS the restart
        # under test -- so on any earlier failure a 900 MB JVM would outlive
        # the run, once per debugging attempt. Two of them, now. Reaping an
        # already-reaped Popen is a no-op, so this is safe on the happy path.
        for p in (proc, proc2):
            if p:
                p.kill()
                p.wait(timeout=15)
        srv.stop()
