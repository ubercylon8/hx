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
