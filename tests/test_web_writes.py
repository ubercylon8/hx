"""The two acts S8 forbids the agent, and the guard on the way in."""
from __future__ import annotations

from hx.web import app as app_mod

ORIGIN = {"Origin": "http://127.0.0.1:8901"}


def _finding(conn, fid="f1", status="new"):
    eid = conn.execute("SELECT id FROM engagement").fetchone()[0]
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES(?,?,?,'Missing HSTS','Low','Firm','check',?,'surface')",
        (fid, eid, f"k-{fid}", status))
    return eid


def _status(conn, fid="f1"):
    return conn.execute("SELECT status FROM finding WHERE id=?",
                        (fid,)).fetchone()[0]


def _events(conn, fid="f1"):
    return conn.execute(
        "SELECT COUNT(*) FROM finding_status_event WHERE finding_id=?",
        (fid,)).fetchone()[0]


def test_a_same_origin_post_confirms_the_finding(client, alpha_db):
    _finding(alpha_db)

    response = client.post("/e/alpha/findings/f1/status",
                           data={"status": "confirmed"}, headers=ORIGIN,
                           follow_redirects=False)

    assert response.status_code == 303
    assert _status(alpha_db) == "confirmed"


def test_a_post_with_no_origin_is_refused_and_changes_nothing(
        client, alpha_db):
    """THE STATUS ASSERTION IS THE TEST. A 403 alone passes a handler that
    writes the row and then rejects, which is exactly the bug this guards.

    MUTATION: delete the `_same_origin` branch from `_guard`. This test
    must go red.
    """
    _finding(alpha_db)

    response = client.post("/e/alpha/findings/f1/status",
                           data={"status": "confirmed"},
                           follow_redirects=False)

    assert response.status_code == 403
    assert _status(alpha_db) == "new"
    assert _events(alpha_db) == 0


def test_a_post_from_another_origin_is_refused_and_changes_nothing(
        client, alpha_db):
    """Another web app on this machine is not this web app. Checking the
    origin's HOST against the allowlist rather than the full origin would
    let `http://localhost:9999` write here.

    MUTATION: compare only the origin's hostname against ALLOWED_HOSTS
    instead of the whole origin against this request's own. Must go red.
    """
    _finding(alpha_db)

    for hostile in ("http://localhost:9999", "https://attacker.example",
                    "http://127.0.0.1:9999", "null"):
        response = client.post("/e/alpha/findings/f1/status",
                               data={"status": "confirmed"},
                               headers={"Origin": hostile},
                               follow_redirects=False)
        assert response.status_code == 403, hostile

    assert _status(alpha_db) == "new"
    assert _events(alpha_db) == 0


def test_a_cross_site_fetch_metadata_header_is_refused(client, alpha_db):
    """`Sec-Fetch-Site` is the browser's own account of where a request came
    from, and it wins over `Origin` when present because a page cannot
    forge it."""
    _finding(alpha_db)

    response = client.post(
        "/e/alpha/findings/f1/status", data={"status": "confirmed"},
        headers={**ORIGIN, "Sec-Fetch-Site": "cross-site"},
        follow_redirects=False)

    assert response.status_code == 403
    assert _status(alpha_db) == "new"


def test_a_forged_fetch_metadata_paired_with_a_mismatched_origin_is_refused(
        client, alpha_db):
    """`Sec-Fetch-Site` cannot be forged by a PAGE, but nothing stops a
    non-browser client from sending an honest `same-origin` next to a
    mismatched `Origin` -- no real browser produces that pairing. Trusting
    `Sec-Fetch-Site` alone whenever it is present would accept it anyway;
    the two must AGREE when both are on the wire.

    MUTATION: in `_same_origin`, return `fetch_site == "same-origin"`
    unconditionally instead of also requiring Origin agreement when both
    headers are present. This test must go red, while
    `test_a_cross_site_fetch_metadata_header_is_refused` and
    `test_a_same_origin_post_confirms_the_finding` both stay green.
    """
    _finding(alpha_db)

    response = client.post(
        "/e/alpha/findings/f1/status", data={"status": "confirmed"},
        headers={"Origin": "https://attacker.example",
                "Sec-Fetch-Site": "same-origin"},
        follow_redirects=False)

    assert response.status_code == 403
    assert _status(alpha_db) == "new"
    assert _events(alpha_db) == 0


def test_a_multipart_body_is_refused(client, alpha_db):
    """The app accepts ONE content type on a path that can change something.
    `python-multipart` is deliberately absent, so `request.form()` would
    RAISE here rather than refuse -- which is why these routes read the body
    themselves.

    MUTATION: drop the content-type check from `_form_fields`. Must go red.
    """
    _finding(alpha_db)

    response = client.post("/e/alpha/findings/f1/status",
                           files={"status": ("x.txt", b"confirmed")},
                           headers=ORIGIN, follow_redirects=False)

    assert response.status_code == 415
    assert _status(alpha_db) == "new"
    assert _events(alpha_db) == 0


def test_an_oversized_form_body_is_refused(client, alpha_db):
    """`request.body()` has already buffered the whole thing before
    `_form_fields` ever checks its length, so `MAX_FORM` is a policy limit
    ("a triage note this large is not legitimate"), not a memory guard --
    but the refusal must still land before any write, same as every other
    refusal in this file, and it must be answered 413 rather than
    collapsed into the 415 that means something else (wrong content type,
    which this body did not have).

    MUTATION: delete the `len(body) > MAX_FORM` check from `_form_fields`
    (or make it always False). This test must go red.
    """
    _finding(alpha_db)
    oversized = "note=" + "a" * (app_mod.MAX_FORM + 1)

    response = client.post(
        "/e/alpha/findings/f1/status", content=oversized,
        headers={**ORIGIN,
                "Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False)

    assert response.status_code == 413
    assert _status(alpha_db) == "new"
    assert _events(alpha_db) == 0


def test_reads_are_not_affected_by_the_origin_check(client):
    """The control. A guard applied to GET would make the whole app
    unusable from a link, and every other test here would still pass."""
    assert client.get("/e/alpha").status_code == 200


def test_dismissing_without_a_note_is_refused_over_http(client, alpha_db):
    _finding(alpha_db)

    response = client.post("/e/alpha/findings/f1/status",
                           data={"status": "false_positive", "note": "  "},
                           headers=ORIGIN, follow_redirects=False)

    assert response.status_code == 400
    assert "note is required" in response.text
    assert _status(alpha_db) == "new"
    assert _events(alpha_db) == 0


def test_a_dismissal_with_a_note_records_it(client, alpha_db):
    _finding(alpha_db)

    client.post("/e/alpha/findings/f1/status",
                data={"status": "false_positive",
                      "note": "header is set at the CDN"},
                headers=ORIGIN, follow_redirects=False)

    assert _status(alpha_db) == "false_positive"
    assert alpha_db.execute(
        "SELECT note FROM finding_status_event WHERE finding_id='f1'"
    ).fetchone()[0] == "header is set at the CDN"


def test_a_status_outside_the_two_is_refused_over_http(client, alpha_db):
    _finding(alpha_db)

    response = client.post("/e/alpha/findings/f1/status",
                           data={"status": "reported"}, headers=ORIGIN,
                           follow_redirects=False)

    assert response.status_code == 400
    assert _status(alpha_db) == "new"


def test_stop_writes_the_sentinel_and_an_operator_row(
        client, alpha_db, web_base):
    """STOP is a route over `halt.OperatorHalt`, unchanged. The sentinel is
    the mechanism that actually stops the extension -- it polls the file and
    it works when the bridge is dead -- and the row is what explains the
    stop afterwards."""
    response = client.post("/e/alpha/halt", data={"reason": "client called"},
                           headers=ORIGIN, follow_redirects=False)

    assert response.status_code == 303
    assert (web_base / "alpha" / "HALTED").exists()
    row = alpha_db.execute(
        "SELECT actor, tool, why FROM agent_action WHERE tool='halt'"
    ).fetchone()
    assert row[0] == "operator"
    assert row[2] == "client called"


def test_a_halted_engagement_says_so_on_the_overview(client, web_base):
    """S4: an unreadable sentinel IS halted -- "unknown state is stop" --
    and `OperatorHalt.halted` is a union of the file and the store. The
    banner follows that rule rather than inventing an "unknown"."""
    (web_base / "alpha" / "HALTED").write_text("stopped by hand\n1\n")

    body = client.get("/e/alpha").text

    assert "HALTED" in body
    assert "stopped by hand" in body
    assert "hx resume" in body


def test_a_healthy_engagement_offers_the_stop_button(client):
    """The other half of the union: nothing halted means the STOP form
    renders and the banner does not. Without this test,
    `test_a_halted_engagement_says_so_on_the_overview` cannot tell "the
    banner tracks halt state" apart from "the banner is always on".

    MUTATION: hardcode `data["halted"] = True` in the overview handler.
    This test must go red.
    """
    body = client.get("/e/alpha").text

    assert "HALTED" not in body
    assert 'action="/e/alpha/halt"' in body
    assert "STOP issuance" in body


def test_a_halt_recorded_only_in_the_store_still_shows(client, alpha_db):
    """`OperatorHalt.halted` is a union of the STORE and the sentinel FILE,
    and the union is load-bearing in both directions: an operator can
    `touch` the sentinel from a shell when the bridge is dead (a file with
    no row behind it), and a harness can die between writing the row and
    writing the file (a row with no sentinel on disk). This is the second
    case -- the row lands, the file never does -- written directly the way
    `OperatorHalt.halt()` orders its own two writes, so the test does not
    depend on that method to prove the READ side of the union.

    MUTATION: change `data["halted"] = halt_state.halted` to
    `data["halted"] = halt_state.sentinel_path.exists()` in the overview
    handler. This test must go red.
    """
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO agent_action(id, engagement_id, run_id, ts_us, actor,"
        " tool, why) VALUES('a-store-only', ?, NULL, 1, 'operator', 'halt',"
        " 'stopped from the store')", (eid,))

    body = client.get("/e/alpha").text

    assert "HALTED" in body
    assert "stopped from the store" in body


def test_stop_is_refused_cross_origin(client, web_base):
    """MUTATION: exempt `/halt` from the guard. Must go red."""
    response = client.post("/e/alpha/halt", data={"reason": "x"},
                           headers={"Origin": "https://attacker.example"},
                           follow_redirects=False)

    assert response.status_code == 403
    assert not (web_base / "alpha" / "HALTED").exists()
