"""http.send against a real extension.

ONE TEST, AND IT IS THE ONE A FAKE CANNOT DO: that the bytes this side
composes are bytes the extension accepts, decides about, and issues -- and
that the row written afterwards names an exchange whose blobs are readable.
Every refusal class is proved against `FakeBridge` in the unit suite, because
a loopback target will never produce most of them.
"""
import pytest

from hx.tools import dispatch as dispatch_mod
from hx.tools import impl  # noqa: F401


@pytest.mark.integration
def test_send_reaches_a_loopback_target_and_records_a_readable_exchange(
        tool_session, target):
    # `/health` rather than the brief's `/`: `TargetServer` answers `/` with
    # a bare 404 (`tests/test_target_server.py` pins it -- "a 404 here would
    # leave the integration [...] this suite relies on") and this test wants
    # a 200 to assert on. `/health` is the route built for exactly that.
    env = dispatch_mod.dispatch(
        tool_session, "http.send",
        {"host": target.host, "port": target.port, "method": "GET",
         "path": "/health"},
        why="prove the composed request survives the extension")
    assert env.outcome == "ok", env.as_dict()
    assert env.result["status"] == 200

    # FIX ROUND 1'S FINDING 5. A 200 alone only proves SOMETHING answered --
    # a Burp that, say, answered from a cached response or a different
    # listener would still produce one. `target.hits` is the one witness on
    # this side of the extension no state on the hx side can fake (the same
    # argument `Rig.send_unguarded`'s own docstring makes for using it): it
    # is what the loopback SERVER itself recorded, before it ever answered.
    assert len(target.hits) == 1, "the target never received the request"
    hit = target.hits[0]
    assert hit.method == "GET"
    assert hit.path == "/health"

    row = tool_session.conn.execute(
        "SELECT via, req_blob, resp_blob FROM exchange WHERE id=?",
        (env.result["exchange_id"],)).fetchone()
    assert row[0] == "send"
    # THE BLOBS ARE READ BACK, not merely asserted non-null: a digest naming
    # a blob the store cannot return is exactly the corruption a report would
    # read as evidence.
    assert tool_session.blobs.get(row[1])
    assert tool_session.blobs.get(row[2])
