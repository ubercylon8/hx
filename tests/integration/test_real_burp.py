import hashlib

import pytest

from hx.bridge import server
from tests.integration import burp_fixture as bf

pytestmark = pytest.mark.integration


@pytest.mark.skipif(not bf.burp_available(),
                    reason=f"missing: {', '.join(bf.missing())}")
def test_real_burp_dials_in_and_handshakes(tmp_path):
    """The whole point of this plan, proved against the real container.

    Fakes prove the logic; only this proves Burp actually loads the extension
    and that the socket handshake works end to end.
    """
    srv = server.BridgeServer(tmp_path / "hx.sock", engagement_id="e-integration")
    srv.start()
    proc = None
    try:
        proc = bf.launch_burp(srv.socket_path, "e-integration", tmp_path)

        assert bf.wait_for(lambda: srv.state == "connected"), \
            "Burp never completed the hello handshake"

        assert srv.hello["engagement_id"] == "e-integration"
        assert srv.hello["instance_id"] == "integration"
        assert "2026" in srv.hello["burp_version"], srv.hello
        assert srv.peer_uid is not None

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
    extension knows nothing, because extensionData does not survive."""
    srv = server.BridgeServer(tmp_path / "hx.sock", engagement_id="e-restart")
    srv.start()
    proc = None
    try:
        proc = bf.launch_burp(srv.socket_path, "e-restart", tmp_path)
        assert bf.wait_for(lambda: srv.state == "connected")
        srv.configure({"scope.include": ["https://a/*"]},
                      scope_sha256="abc", profile="production")
        assert srv.state == "configured"

        proc.kill()
        proc.wait(timeout=15)
        assert bf.wait_for(lambda: srv.state == "waiting", timeout=30), \
            "dropped connection must return the bridge to DENY-ALL"
        assert srv.config_epoch == 0
    finally:
        # The kill above is inside the try for a reason -- it IS the restart
        # under test -- so on any earlier failure a 900 MB JVM would outlive
        # the run, once per debugging attempt. Reaping an already-reaped
        # Popen is a no-op, so this is safe on the happy path too.
        if proc:
            proc.kill()
            proc.wait(timeout=15)
        srv.stop()
