"""Spec section 4: what this app can leak, and to whom.

The app renders response bodies captured from a client's application.
Those bodies are attacker-influenced BY DEFINITION -- half the check corpus
exists to find places where attacker input comes back in them -- into a
browser with no authentication in front of it. Each test below names the
mutation that must turn it red; a security test whose failure mode you
cannot state is decoration.
"""
from __future__ import annotations

import sqlite3

import pytest

from hx.web import app as app_mod
from hx.web import registry as registry_mod


def test_the_loopback_host_is_served(client):
    """The control. Without it, a middleware that refused EVERYTHING would
    pass every other test in this file."""
    assert client.get("/").status_code == 200


def test_a_foreign_host_header_is_refused(client):
    """DNS REBINDING. Binding 127.0.0.1 stops remote packets; it does not
    stop a page the operator is browsing from issuing requests to
    127.0.0.1:PORT. A hostile site that resolves its OWN name to 127.0.0.1
    gets same-origin access to every engagement this app can reach. S4 wrote
    the shape of this down for the bridge -- "a loopback port is reachable
    by any local process or browser tab" -- which is why the bridge is a
    Unix socket. A web app cannot be one.

    MUTATION: delete the `hostname(...) not in ALLOWED_HOSTS` branch from
    `_guard`. This test must go red.
    """
    response = client.get("/", headers={"Host": "attacker.example"})
    assert response.status_code == 421
    assert "Alpha Inc" not in response.text


def test_a_host_header_may_carry_a_port(client):
    assert client.get("/", headers={"Host": "127.0.0.1:8901"}).status_code == 200
    assert client.get("/", headers={"Host": "localhost:9"}).status_code == 200


def test_a_host_that_merely_starts_with_an_allowed_name_is_refused(client):
    """`127.0.0.1.attacker.example` is not `127.0.0.1`, and a prefix or
    substring test would say it was.

    MUTATION: change `hostname(...) not in ALLOWED_HOSTS` to
    `not any(h in host for h in ALLOWED_HOSTS)`. This test must go red.
    """
    for hostile in ("127.0.0.1.attacker.example", "localhost.attacker.example",
                    "attacker.example:127.0.0.1"):
        assert client.get("/", headers={"Host": hostile}).status_code == 421


def test_every_response_carries_the_content_security_policy(client):
    """Defence in depth behind autoescape. `default-src 'none'` means a
    rendered `<img src=x onerror=...>` has nothing to load and nothing to
    run, and `script-src 'none'` is honest for Plan A: it ships no
    JavaScript. Plan B widens that to 'self' when it vendors htmx, where a
    reviewer can see it happen.

    MUTATION: delete the `Content-Security-Policy` line from `_secured`.
    """
    csp = client.get("/").headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp


def test_a_refusal_carries_the_headers_too(client):
    """"Every response" has to mean every response, and a refusal is exactly
    the response that returns EARLY -- skipping whatever the success path
    does on its way out. The 421 is what a rebinding attack receives.

    MUTATION: in `_guard`, return the refusal directly instead of through
    `_secured`. This test must go red while the one above stays green, which
    is the whole reason both exist.
    """
    refused = client.get("/", headers={"Host": "attacker.example"})
    assert refused.status_code == 421
    assert "default-src 'none'" in refused.headers["content-security-policy"]
    assert refused.headers["x-content-type-options"] == "nosniff"


def test_every_response_forbids_content_sniffing(client):
    """MUTATION: delete the `X-Content-Type-Options` line from `_secured`."""
    assert client.get("/").headers["x-content-type-options"] == "nosniff"


def test_a_hostile_client_name_is_escaped_and_not_executed(web_base):
    """THE CORE THREAT, at its cheapest reachable point. `hx new --client`
    takes a string off the command line and the engagements list renders it.
    The same escaping is what stands between a captured response body and
    the operator's browser on the exchange screen.

    MUTATION: pass `autoescape=False` in `render.templates()`. This test
    must go red -- and note that it asserts the RAW form is ABSENT, not
    merely that an escaped form is present, because a page can contain both.
    """
    from hx import config as config_mod
    from hx import engagement as eng_mod
    from starlette.testclient import TestClient

    from hx.web.app import create_app

    payload = "<script>alert(document.domain)</script>"
    cfg = config_mod.Config(name="evil", client=payload,
                            safety_profile="staging",
                            scope_include=["https://app.test/*"])
    eng_mod.create(web_base / "evil", cfg, author="test").db.close()

    with TestClient(create_app(web_base),
                    base_url="http://127.0.0.1:8901") as c:
        body = c.get("/").text

    assert payload not in body
    assert "&lt;script&gt;" in body


def test_the_read_path_cannot_write(web_base):
    """`connect(readonly=True)` opens `file:...?mode=ro`, so a write raises
    at the SQLite layer. This store is EVIDENCE, and `scope_version` and
    `finding_status_event` are append-only because someone may one day
    dispute what it says. A reader that CANNOT write is a stronger claim
    than one that merely does not.

    MUTATION: change `readonly=True` to `readonly=False` in
    `registry.open_read`. This test must go red.
    """
    entry = registry_mod.lookup(web_base, "alpha")
    conn = registry_mod.open_read(entry)
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("UPDATE engagement SET client='changed'")
    finally:
        conn.close()


@pytest.mark.parametrize("name", [
    # A literal ".." is deliberately absent from this list: httpx2's URL
    # class applies RFC 3986 dot-segment removal (`remove_dot_segments`)
    # at request-construction time -- MEASURED 2026-09-01, by inspecting
    # `httpx2.Client._merge_url` and `URL.copy_with` directly -- so
    # `client.get("/e/..")` collapses to `client.get("/")` before a byte
    # leaves this process. Every conforming HTTP client, including a
    # browser, does the same normalisation, so this exact byte sequence
    # cannot reach any server over HTTP. `test_web_registry.py`'s
    # `test_lookup_refuses_a_name_the_scan_did_not_return` still exercises
    # `registry.lookup(base, "..")` directly, at the layer where it matters.
    "%2e%2e", "..%2f..%2fetc", "alpha%2f..%2f..", "beta%00", "ALPHA",
])
def test_a_name_the_scan_did_not_return_is_a_404(client, name):
    """THE REGISTRY SCAN IS THE ALLOWLIST. Not a sanitiser over a path join.

    MUTATION: replace `registry.lookup(base, name)` in the overview handler
    with an entry built from `base / name`. This test must go red.
    """
    assert client.get(f"/e/{name}").status_code == 404


def test_the_hostname_helper_splits_ports_and_brackets():
    """A unit test beside the integration ones, because the parsing is where
    a Host check goes wrong quietly."""
    assert app_mod.hostname("127.0.0.1") == "127.0.0.1"
    assert app_mod.hostname("127.0.0.1:8901") == "127.0.0.1"
    assert app_mod.hostname(" localhost:80 ") == "localhost"
    assert app_mod.hostname("[::1]:8901") == "[::1]"
    assert app_mod.hostname("") == ""
