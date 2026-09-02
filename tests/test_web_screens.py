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
