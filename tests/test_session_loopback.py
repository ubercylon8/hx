"""Loopback-only listeners, and the config that asks for them.

Two facts live here because they are one control. `write_listener_config`
WRITES the request -- `listen_mode: loopback_only`, on two listeners that must
not be the same listener -- and `not_loopback_only` MEASURES what Burp
actually bound. Neither is worth anything without the other: the string is not
self-enforcing (changing it to `all_interfaces` once left the whole suite
green with the proxy bound to `*`), and the check has nothing to check if the
config never asked.

No JVM starts here. `_free_port` really binds, to `127.0.0.1:0`, and closes
the socket before it returns.
"""
import json

import pytest

from hx import session


def test_a_loopback_only_listener_passes(monkeypatch):
    monkeypatch.setattr(session, "_listening_sockets",
                        lambda pid: ["127.0.0.1:8080", "[::1]:8081"])
    assert session.not_loopback_only(1, [8080, 8081]) is None


def test_a_listener_on_all_interfaces_is_named(monkeypatch):
    monkeypatch.setattr(session, "_listening_sockets",
                        lambda pid: ["0.0.0.0:8080"])
    why = session.not_loopback_only(1, [8080])
    assert why and "8080" in why


def test_a_listener_on_a_routable_address_is_named(monkeypatch):
    monkeypatch.setattr(session, "_listening_sockets",
                        lambda pid: ["192.168.1.10:8080"])
    assert session.not_loopback_only(1, [8080]) is not None


# --- the config the listeners come from ----------------------------------


def _listeners(workdir):
    cfg = json.loads((workdir / session.PROXY_CONFIG).read_text())
    return cfg["proxy"]["request_listeners"]


def test_every_listener_asks_for_loopback_only(tmp_path):
    """The one string that decides where Burp binds, pinned in the FAST suite.

    Mutating it to `all_interfaces` left `pytest -q` completely green: 973
    passed, with the only witness the 210-second integration suite, which
    catches it through `ss` against a real Burp. `tests/test_session.py` writes
    the string into a fake config the product never produced, and
    `tests/test_burp_fixture.py` only asserts the word appears in a failure
    MESSAGE -- so nothing here read what `write_listener_config` actually
    wrote. It is product code in `src/` now, and a proxy listener on `0.0.0.0`
    is an open forward relay on whatever network the laptop is attached to.
    """
    session.write_listener_config(tmp_path)
    listeners = _listeners(tmp_path)
    assert len(listeners) == 2, (
        "a config naming only the second listener leaves the first wherever "
        "Burp's defaults put it, which is the 8080 _free_port() exists to avoid")
    assert [l["listen_mode"] for l in listeners] == ["loopback_only"] * 2
    assert all(l["running"] for l in listeners)


def test_the_operator_and_the_crawler_never_get_one_port(monkeypatch, tmp_path):
    """F2: two ephemeral binds in a row can return the same number.

    Measured at this call site: 4 collisions in 20 000 calls. Forced here
    rather than waited for -- `_free_port` hands back one repeat and then two
    distinct numbers, which is exactly the draw that used to be written
    straight into the config. `Source.forListenerPort` is `port == crawlerPort
    ? CRAWLER : OPERATOR`, so one port for both would give the consultant's
    own browsing the agent's rule set, and nothing downstream compares them.
    """
    draws = iter([41001, 41001, 41002, 41003])
    monkeypatch.setattr(session, "_free_port", lambda: next(draws))

    ports = session.write_listener_config(tmp_path)

    assert ports[0] != ports[1], "the collision was written into the config"
    assert ports == [41002, 41003], (
        "the colliding pair must be redrawn as a PAIR: keeping the first and "
        "redrawing only the second would hand back a port the kernel has "
        "already offered once")
    assert [l["listener_port"] for l in _listeners(tmp_path)] == ports


def test_a_draw_that_cannot_separate_them_is_fatal_not_silent(
        monkeypatch, tmp_path):
    """Never silent. `_free_port` here is stuck, and the session must not
    start at all rather than start with one listener serving both roles."""
    monkeypatch.setattr(session, "_free_port", lambda: 41001)

    with pytest.raises(session.SessionError) as exc:
        session.write_listener_config(tmp_path)
    assert "41001" in str(exc.value)
    assert "crawler" in str(exc.value)


def test_a_named_crawler_port_is_honoured_and_still_separated(
        monkeypatch, tmp_path):
    """`second_port` is the rig's way of pinning the crawler's listener.

    It must survive the redraw -- a caller that named a port and got another
    one back would have its `-Dhx.crawler_port` and its listener disagree --
    and the FIRST port is the one that moves when the two collide.
    """
    draws = iter([41001, 41002])
    monkeypatch.setattr(session, "_free_port", lambda: next(draws))

    ports = session.write_listener_config(tmp_path, 41001)

    assert ports == [41002, 41001]
