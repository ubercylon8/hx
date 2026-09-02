"""The screen half of `test_credentials_never_reach_the_store.py`.

Section 7's rule -- a credential value never appears in config.yaml, a
rendered report, `agent_action`, or any log -- has one more surface since
2026-09-01, and it is the one an operator looks at all day.

TWO MECHANISMS, AND ONLY ONE OF THEM IS THIS APP'S. Blob BYTES are redacted
extension-side by `Redactor.java` BEFORE hashing, so what reaches the
exchange screen already carries `{{identity:<id>:authz}}` where a credential
was; this app adds nothing there, and S4 forbids it to -- "Python must never
gain a second place that decides any of them". What IS this app's job is the
URL COLUMNS, where `http://user:pass@host/` reached `exchange.url` and
`denial.url` verbatim until `records.redact_url` was written. The screen
calls that same function and no other.
"""
from __future__ import annotations

SECRET = "hunter2correcthorse"


def _exchange_with_userinfo(conn, eid):
    conn.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r1',?,'scan','staging',1,'completed')", (eid,))
    conn.execute(
        "INSERT INTO exchange(id, run_id, via, outcome, sent_us, method, url,"
        " status) VALUES('x1','r1','send','ok',1,'GET',"
        f"'https://admin:{SECRET}@alpha.test/panel',200)")


def test_url_userinfo_never_reaches_the_exchange_screen(client, alpha_db):
    """MUTATION: remove `| redact` from the URL in `exchange.html`.
    This test must go red."""
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _exchange_with_userinfo(alpha_db, eid)

    body = client.get("/e/alpha/exchanges/x1").text

    assert SECRET not in body
    assert "alpha.test/panel" in body


def test_url_userinfo_never_reaches_the_finding_screen(client, alpha_db):
    """The same secret, one screen along. Two halves of one request redacted
    by two different rules is how a page ends up quoting the credential out
    of the column beside the blob that does not have it."""
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _exchange_with_userinfo(alpha_db, eid)
    alpha_db.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES('f1',?,'k1','Exposed panel','High','Firm','check','new',"
        "'surface')", (eid,))
    alpha_db.execute(
        "INSERT INTO evidence(id, finding_id, seq, role, kind, exchange_id,"
        " captured_us) VALUES('ev1','f1',1,'proof','exchange','x1',1)")

    body = client.get("/e/alpha/findings/f1").text

    assert SECRET not in body


def test_the_scope_patterns_on_the_overview_are_redacted(client, web_base):
    """Standing ruling R1 from the report's own review: text an OPERATOR
    authored is not exempt. A credential reaches a scope pattern the same
    way it reaches a `--client` string.

    MUTATION: remove `| redact` from the scope list in `overview.html`.
    """
    from hx import config as config_mod
    from hx import engagement as eng_mod
    from starlette.testclient import TestClient

    from hx.web.app import create_app

    cfg = config_mod.Config(
        name="creds", client="C", safety_profile="staging",
        scope_include=[f"https://admin:{SECRET}@creds.test/*"])
    eng_mod.create(web_base / "creds", cfg, author="test").db.close()

    with TestClient(create_app(web_base),
                    base_url="http://127.0.0.1:8901") as c:
        body = c.get("/e/creds").text

    assert SECRET not in body
    assert "creds.test" in body
