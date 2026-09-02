"""Each screen shows the right data, not merely a 200."""
from __future__ import annotations


def test_the_index_lists_both_engagements_with_their_clients(client):
    body = client.get("/").text
    assert "alpha" in body and "Alpha Inc" in body
    assert "beta" in body and "Beta Ltd" in body


def test_the_overview_names_the_engagement_and_its_scope_hash(client, alpha_db):
    sha = alpha_db.execute(
        "SELECT sha256 FROM scope_version").fetchone()[0]
    body = client.get("/e/alpha").text
    assert "Alpha Inc" in body
    assert sha in body


def test_an_unscanned_engagement_says_so_rather_than_showing_a_clean_bill(
        client):
    """S12. Silence where coverage should be reads as coverage."""
    body = client.get("/e/alpha").text
    assert "not been scanned" in body


def test_a_captured_but_untested_surface_is_named_not_just_counted(
        client, alpha_db):
    """The half of S12 a count cannot carry: "did you test the password
    reset flow?" needs the surface NAMED."""
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES('s1',?,'POST','https','alpha.test',443,'/password/reset',"
        "'proxy',2)", (eid,))

    body = client.get("/e/alpha").text

    assert "/password/reset" in body
    assert "Never tested" in body


def test_a_run_with_drops_says_its_numbers_are_a_floor(client, alpha_db):
    """S5: a run with drops has coverage numbers that are a FLOOR, not a
    count, and the warning sits beside the figures it qualifies."""
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status, requests_issued, dropped_total)"
        " VALUES('r1',?,'scan','staging',1,'completed',10,3)", (eid,))

    body = client.get("/e/alpha").text

    assert "floor" in body.lower()
    assert "3 exchange(s) were dropped" in body


def test_a_running_run_with_a_dead_heartbeat_renders_as_error(
        client, alpha_db):
    """S5 again: "an aborted run must never render as a clean one, and
    neither must one that merely STOPPED BEING UPDATED". The screen cannot
    reap it -- its connections are read-only -- so it must render the truth
    without writing it.

    MUTATION: make `reads._run_rows` return `row[2]` unconditionally. This
    test must go red.
    """
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status, heartbeat_us, requests_issued, dropped_total)"
        " VALUES('r1',?,'scan','staging',1,'running',1,0,0)", (eid,))

    body = client.get("/e/alpha").text

    assert "status-error" in body
    assert "status-running" not in body


def test_the_overview_reads_the_engagement_the_url_names(client, alpha_db):
    """Two engagements exist; `beta` must not show `alpha`'s client."""
    assert "Alpha Inc" not in client.get("/e/beta").text
    assert "Beta Ltd" in client.get("/e/beta").text


def test_the_coverage_figures_match_what_the_report_computes(
        client, alpha_db):
    """THE TEST THE EXTRACTION EXISTS FOR. One store, two renderers, the
    same numbers. A second coverage query would drift, and the drift would
    show a reassuring figure on exactly the engagements the report warns
    about."""
    from hx import coverage as coverage_mod

    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES('s1',?,'GET','https','alpha.test',443,'/a','proxy',2)", (eid,))
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status, requests_issued, dropped_total)"
        " VALUES('r1',?,'scan','staging',1,'completed',1,0)", (eid,))
    alpha_db.execute(
        "INSERT INTO check_run(id, run_id, surface_id, check_id,"
        " check_version, verdict) VALUES('c1','r1','s1','missing-hsts','1',"
        "'clean')")

    cov = coverage_mod.facts(alpha_db, eid)
    body = client.get("/e/alpha").text

    assert cov.captured == 1
    assert f"{cov.captured} surface(s) captured" in body
    assert "missing-hsts" in body
    assert "Never tested" not in body


def _surface(conn, eid, sid="s1", method="GET", template="/a"):
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES(?,?,?,'https','alpha.test',443,?,'proxy',2)",
        (sid, eid, method, template))


def _finding(conn, eid, fid="f1", severity="High", status="new",
             title="Reflected input", surface_id=None):
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level, surface_id,"
        " check_id) VALUES(?,?,?,?,?,'Firm','check',?,'surface',?,'refl')",
        (fid, eid, f"k-{fid}", title, severity, status, surface_id))


def test_the_surface_screen_names_each_surface_and_how_it_was_found(
        client, alpha_db):
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _surface(alpha_db, eid, template="/order/{id}")

    body = client.get("/e/alpha/surfaces").text

    assert "/order/{id}" in body
    assert "proxy" in body


def test_a_surface_whose_only_check_row_is_skipped_shows_no_answers(
        client, alpha_db):
    """`answered` counts only verdicts in `coverage.ANSWERED`. A `skipped`
    row records a GAP -- the budget cut the scan off before it -- and
    counting it would make the column say a check ran when none did.

    MUTATION: drop the `verdict IN (...)` clause from `reads.surfaces`.
    This test must go red.
    """
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _surface(alpha_db, eid)
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r1',?,'scan','staging',1,'completed')", (eid,))
    alpha_db.execute(
        "INSERT INTO check_run(id, run_id, surface_id, check_id,"
        " check_version, verdict) VALUES('c1','r1','s1','x','1','skipped')")

    from hx.web import reads as reads_mod
    from hx.web import registry as registry_mod

    conn = registry_mod.open_read(registry_mod.lookup(
        client.app.state.base, "alpha"))
    try:
        assert reads_mod.surfaces(conn, eid)[0]["answered"] == 0
    finally:
        conn.close()


def test_the_findings_screen_orders_by_severity(client, alpha_db):
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _finding(alpha_db, eid, fid="f-low", severity="Low", title="Low one")
    _finding(alpha_db, eid, fid="f-crit", severity="Critical",
             title="Critical one")

    body = client.get("/e/alpha/findings").text

    assert body.index("Critical one") < body.index("Low one")


def test_filtering_by_status_hides_the_others(client, alpha_db):
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _finding(alpha_db, eid, fid="f-new", status="new", title="Still new")
    _finding(alpha_db, eid, fid="f-fp", status="false_positive",
             title="Already dismissed")

    body = client.get("/e/alpha/findings?status=false_positive").text

    assert "Already dismissed" in body
    assert "Still new" not in body


def test_an_unknown_filter_value_is_refused_rather_than_ignored(client):
    """A screen that silently drops a filter shows MORE than was asked for
    while looking obedient, and "I filtered to confirmed and saw none"
    becomes a false statement about the data.

    MUTATION: make `findings` ignore an unrecognised value instead of
    raising. This test must go red.
    """
    response = client.get("/e/alpha/findings?status=definitely_fine")
    assert response.status_code == 400
    assert "false_positive" in response.text


def test_the_findings_screen_shows_the_current_status(client, alpha_db):
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _finding(alpha_db, eid, fid="f1", status="confirmed")

    assert "confirmed" in client.get("/e/alpha/findings").text
