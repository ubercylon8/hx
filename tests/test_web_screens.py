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
    """THE TEST THE EXTRACTION EXISTS FOR. One store, two renderers -- the
    overview screen and `report.render`, the actual deliverable -- the same
    numbers. A second coverage query in either one would drift, and the
    drift would show a reassuring figure on exactly the engagements the
    other surface warns about.

    The fixture has three surfaces, not one, so a wrong implementation has
    somewhere to diverge: one answered (`clean`), one with only a `skipped`
    check_run (a GAP, not an answer -- S12's distinction, and the reason
    `verdict IN (...)` exists), and one with no check_run at all. Both
    renderers must report the same captured/answered/untested split and
    name the same two untested surfaces.

    MUTATION: replace `coverage_mod.facts(conn, engagement_id)` inside
    `reads.overview` with `overview`'s own inline queries computing the same
    thing (the extraction this test exists for, undone). This test must go
    red -- the screen and the report would still individually be self
    -consistent, but the numbers only need to be tested once for that; this
    test's job is to fail unless the SCREEN's numbers were computed the way
    the REPORT's were.
    """
    from hx import config as config_mod
    from hx import report as report_mod
    from hx.web import registry as registry_mod

    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    for sid, method, template in (("s1", "GET", "/a"), ("s2", "POST", "/b"),
                                  ("s3", "GET", "/c")):
        alpha_db.execute(
            "INSERT INTO surface(id, engagement_id, method, scheme, host,"
            " port, path_template, discovered_by, normaliser_version)"
            " VALUES(?,?,?,'https','alpha.test',443,?,'proxy',2)",
            (sid, eid, method, template))
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status, requests_issued, dropped_total)"
        " VALUES('r1',?,'scan','staging',1,'completed',2,0)", (eid,))
    alpha_db.execute(
        "INSERT INTO check_run(id, run_id, surface_id, check_id,"
        " check_version, verdict) VALUES('c1','r1','s1','missing-hsts','1',"
        "'clean')")
    alpha_db.execute(
        "INSERT INTO check_run(id, run_id, surface_id, check_id,"
        " check_version, verdict) VALUES('c2','r1','s2','sql-error','1',"
        "'skipped')")

    entry = registry_mod.lookup(client.app.state.base, "alpha")
    config = config_mod.load(entry.path / "config.yaml")
    report_out = report_mod.render(alpha_db, engagement_id=eid, config=config)
    body = client.get("/e/alpha").text

    for surface in (report_out, body):
        assert "3 surface(s)" in surface
        assert "missing-hsts" in surface
        assert "sql-error" in surface
        assert "POST /b" in surface
        assert "GET /c" in surface
    assert "<strong>1</strong> had at" in body
    assert "<strong>2</strong> had none" in body
    assert "Never tested" in body


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


def test_the_surfaces_screen_warns_when_a_run_has_dropped_exchanges(
        client, alpha_db):
    """S5's floor caveat is not only the overview's: `/e/{name}/surfaces`
    renders per-surface exchange counts and the surface list itself, both
    of which are a floor when any run dropped traffic. The master spec's
    Sec 12 rule is that a count presented without its caveat is worse than
    no report at all.

    MUTATION: delete the `{% if dropped_total %}` block from
    surfaces.html. This test must go red.
    """
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status, requests_issued, dropped_total)"
        " VALUES('r1',?,'scan','staging',1,'completed',10,4)", (eid,))

    body = client.get("/e/alpha/surfaces").text

    assert "floor" in body.lower()
    assert "4 exchange(s) were dropped" in body


def test_the_surfaces_screen_says_nothing_about_drops_when_there_are_none(
        client, alpha_db):
    """The control. Without it, the test above cannot tell "the warning
    tracks drops" apart from "the warning is always on" -- a caveat that
    always fires stops being read.

    MUTATION: hardcode `dropped_total=1` in the surfaces route handler
    (`hx/web/app.py`). This test must go red.
    """
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status, requests_issued, dropped_total)"
        " VALUES('r1',?,'scan','staging',1,'completed',10,0)", (eid,))

    body = client.get("/e/alpha/surfaces").text

    assert "floor" not in body.lower()
    assert "were dropped" not in body


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


def test_an_empty_engagement_says_nothing_was_captured_on_the_surface_screen(
        client):
    """No surface exists yet; the screen must say so rather than rendering
    an empty table with no explanation.

    MUTATION: delete the `{% if not surfaces %}` branch from
    surfaces.html, leaving only the table. This test must go red.
    """
    body = client.get("/e/alpha/surfaces").text
    assert "Nothing captured yet" in body
    assert "<table>" not in body


def test_no_findings_says_so_rather_than_an_empty_table(client):
    """MUTATION: delete the `{% if not findings %}` branch from
    findings.html, leaving only the table. This test must go red.
    """
    body = client.get("/e/alpha/findings").text
    assert "No finding matches" in body
    assert "<table>" not in body


def test_a_host_scoped_finding_shows_its_host_not_a_path_template(
        client, alpha_db):
    """A `host`- or `engagement`-scoped finding has no `surface_id`, so the
    LEFT JOIN's `path_template` is NULL -- `findings.html` falls back to
    the finding's own `host` column rather than rendering a blank cell.

    MUTATION: in findings.html, change the `{% if f.path_template %}`
    branch to always render (drop the `{% else %}` fallback). This test
    must go red.
    """
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level, host)"
        " VALUES('f-host',?,'k-host','Weak TLS config','Medium','Firm',"
        "'check','new','host','weak.alpha.test')", (eid,))

    body = client.get("/e/alpha/findings").text

    assert "weak.alpha.test" in body


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


def test_the_finding_detail_shows_its_evidence_chain(client, alpha_db):
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _finding(alpha_db, eid, fid="f1")
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r1',?,'scan','staging',1,'completed')", (eid,))
    alpha_db.execute(
        "INSERT INTO exchange(id, run_id, via, outcome, sent_us, method, url,"
        " status) VALUES('x1','r1','send','ok',1,'GET',"
        "'https://alpha.test/search?q=1',200)")
    alpha_db.execute(
        "INSERT INTO evidence(id, finding_id, seq, role, kind, exchange_id,"
        " note, captured_us) VALUES('ev1','f1',1,'proof','exchange','x1',"
        "'the payload came back verbatim',1)")

    body = client.get("/e/alpha/findings/f1").text

    assert "the payload came back verbatim" in body
    assert '/e/alpha/exchanges/x1">x1</a>' in body


def test_the_finding_detail_shows_its_status_history(client, alpha_db):
    from hx import triage as triage_mod

    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _finding(alpha_db, eid, fid="f1")
    triage_mod.set_status(alpha_db, finding_id="f1",
                          to_status="false_positive",
                          note="header is set at the CDN")

    body = client.get("/e/alpha/findings/f1").text

    assert "header is set at the CDN" in body
    assert "human" in body


def test_an_unknown_finding_is_a_404(client):
    assert client.get("/e/alpha/findings/f-nope").status_code == 404


def test_an_unknown_exchange_is_a_404(client):
    assert client.get("/e/alpha/exchanges/x-nope").status_code == 404


def test_the_finding_screens_three_empty_states(client, alpha_db):
    """No evidence, no observation and no triage history are three
    different absences, and each gets its own sentence rather than a blank
    table -- pinned together since all three come from one finding with
    nothing attached to it yet.

    MUTATION: change any of the three `{% if not ... %}` guards in
    finding.html to `{% if ... %}`. This test must go red.
    """
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    _finding(alpha_db, eid, fid="f1")

    body = client.get("/e/alpha/findings/f1").text

    assert "No evidence is attached" in body
    assert "No run has recorded an observation" in body
    assert "Never triaged" in body


def test_the_exchange_view_shows_both_halves(client, alpha_db, web_base):
    from hx.store.blobs import BlobStore

    blobs = BlobStore(web_base / "alpha" / "blobs")
    req_digest, req_len = blobs.put(b"GET /search?q=1 HTTP/1.1\r\n"
                                    b"Host: alpha.test\r\n\r\n")
    resp_digest, resp_len = blobs.put(b"HTTP/1.1 200 OK\r\n"
                                      b"Content-Type: text/html\r\n\r\n"
                                      b"<b>hello</b>")
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r1',?,'scan','staging',1,'completed')", (eid,))
    alpha_db.execute(
        "INSERT INTO exchange(id, run_id, via, outcome, sent_us, method, url,"
        " status, req_blob, resp_blob, resp_len)"
        " VALUES('x1','r1','send','ok',1,'GET','https://alpha.test/search',"
        f"200,'{req_digest}','{resp_digest}',{resp_len})")

    body = client.get("/e/alpha/exchanges/x1").text

    assert "Host: alpha.test" in body
    assert "Content-Type: text/html" in body


def test_a_hostile_response_body_is_escaped_not_executed(
        client, alpha_db, web_base):
    """THE CORE THREAT of spec section 4, at the screen it actually lands
    on. A response body is attacker-influenced by definition -- half the
    check corpus exists to find places where attacker input comes back in
    one -- and this app renders it into a browser with no authentication in
    front of it.

    MUTATION: pass `autoescape=False` in `render.templates()`. This test
    must go red. It asserts the RAW form is ABSENT rather than that an
    escaped form is present, because a page can hold both.
    """
    from hx.store.blobs import BlobStore

    payload = b"<script>fetch('/e/beta')</script>"
    blobs = BlobStore(web_base / "alpha" / "blobs")
    digest, length = blobs.put(b"HTTP/1.1 200 OK\r\n\r\n" + payload)
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r1',?,'scan','staging',1,'completed')", (eid,))
    alpha_db.execute(
        "INSERT INTO exchange(id, run_id, via, outcome, sent_us, method, url,"
        " status, resp_blob, resp_len)"
        " VALUES('x1','r1','send','ok',1,'GET','https://alpha.test/',200,"
        f"'{digest}',{length})")

    body = client.get("/e/alpha/exchanges/x1").text

    assert payload.decode() not in body
    assert "&lt;script&gt;" in body


def test_an_unreadable_blob_says_so_rather_than_showing_an_empty_body(
        client, alpha_db):
    """S12 at the level of one panel: a body that could not be read must not
    render as a body that was empty. The exchange row names a digest whose
    file was never written.

    MUTATION: catch `CorruptBlob` and return `b""`. This test must go red.
    """
    eid = alpha_db.execute("SELECT id FROM engagement").fetchone()[0]
    alpha_db.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r1',?,'scan','staging',1,'completed')", (eid,))
    alpha_db.execute(
        "INSERT INTO exchange(id, run_id, via, outcome, sent_us, method, url,"
        " status, resp_blob) VALUES('x1','r1','send','ok',1,'GET',"
        "'https://alpha.test/',200,'" + "0" * 64 + "')")

    body = client.get("/e/alpha/exchanges/x1").text

    assert "could not be read" in body
