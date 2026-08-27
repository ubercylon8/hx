"""One Markdown file, and the section that makes it honest.

S12: a report that cannot distinguish "tested, clean" from "never reached" is
worse than no report. Most of these tests are that sentence, applied.
"""
import sqlite3

import pytest

from hx import config as config_mod
from hx import report
from hx.checks import base
from hx.store import blobs as blobs_mod
from hx.store import db as db_mod
from hx.store import records


# --- fixture plumbing, private to this file ---------------------------------
#
# Hand-built in-memory engagements, the same way `tests/conftest.py`'s
# `engagement_conn` and `tests/test_records_findings.py`'s `key()` build
# theirs: `report.render` reads six tables at once (`engagement`, `run`,
# `finding`, `finding_observation`, `evidence`, `check_run`, `surface`), and
# no existing fixture seeds all of them in the combinations these tests need.

def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.execute("PRAGMA foreign_keys=ON")
    db_mod.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e-1','acme-2026','Acme Corp',1,'active')")
    return conn


def _run(conn, run_id="r-1", *, dropped_total=0) -> None:
    conn.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status, dropped_total) VALUES(?,'e-1','manual','staging',1,"
        "'completed',?)", (run_id, dropped_total))


def _exchange(conn, exchange_id, run_id, url, *, req_blob=None) -> None:
    conn.execute(
        "INSERT INTO exchange(id, run_id, via, outcome, sent_us, method,"
        " url, req_blob) VALUES(?,?,'proxy','ok',1,'GET',?,?)",
        (exchange_id, run_id, url, req_blob))


def _finding(conn, *, run_id, title, severity, exchange_ids,
            check_id=None) -> str:
    c = base.Candidate(title=title, severity=severity, confidence="Firm",
                       insertion=None, exchange_ids=tuple(exchange_ids))
    key = records.dedupe_key(type_=title, scheme="https", host="app.acme.test",
                             port=443, method="GET", path_template="/",
                             insertion_kind=None, insertion_name=None)
    fid = records.upsert_finding(conn, engagement_id="e-1", candidate=c,
                                 dedupe_key=key, run_id=run_id,
                                 check_id=check_id)
    records.record_evidence(conn, finding_id=fid, exchange_ids=exchange_ids,
                            at_us=1)
    return fid


def _config(**over) -> config_mod.Config:
    args = dict(name="acme-2026", client="Acme Corp",
               scope_include=["https://app.acme.test/*"])
    args.update(over)
    return config_mod.Config(**args)


@pytest.fixture
def report_env():
    """A real engagement, nothing captured, nothing scanned. The floor case
    every other fixture is a variation of."""
    conn = _conn()
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": None}
    conn.close()


@pytest.fixture
def report_env_with_findings():
    """One High finding and one Low finding, each with one evidence row, plus
    a `check_run` row for `hx.passive.cookie-flags` so the coverage section
    has something named to find."""
    conn = _conn()
    _run(conn, "r-1")
    _exchange(conn, "x-1", "r-1", "https://app.acme.test/login")
    _exchange(conn, "x-2", "r-1", "https://app.acme.test/")
    _exchange(conn, "x-3", "r-1", "https://app.acme.test/admin")
    _finding(conn, run_id="r-1", title="Reflected XSS in search",
            severity="High", exchange_ids=["x-1"], check_id="hx.test.xss")
    _finding(conn, run_id="r-1", title="Cookie set without HttpOnly",
            severity="Low", exchange_ids=["x-2"],
            check_id="hx.passive.cookie-flags")
    # Medium, alongside High and Low, is what separates "highest severity
    # first" from "alphabetical": High < Low holds under BOTH orderings
    # (H before L either way), so a two-finding fixture cannot tell them
    # apart -- measured directly, sweep row F below. Medium vs Low is the
    # pair that disagrees: severity order wants Medium before Low, and
    # alphabetical order wants Low before Medium ("L" < "M").
    _finding(conn, run_id="r-1", title="Verbose stack trace on error",
            severity="Medium", exchange_ids=["x-3"])
    conn.execute(
        "INSERT INTO check_run(id, run_id, check_id, check_version, verdict,"
        " requests_sent) VALUES('cr-1','r-1','hx.passive.cookie-flags','1',"
        "'finding',0)")
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": None}
    conn.close()


@pytest.fixture
def report_env_skipped():
    """A check the budget cut off before it ran, on a surface no other row
    mentions -- so omitting it from the coverage table would render it as
    tested rather than never reached."""
    conn = _conn()
    _run(conn, "r-1")
    conn.execute(
        "INSERT INTO check_run(id, run_id, check_id, check_version, verdict,"
        " reason) VALUES('cr-1','r-1','hx.test.timing-probe','1','skipped',"
        "'budget')")
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": None}
    conn.close()


@pytest.fixture
def report_env_dropped():
    """A run that lost exchanges in flight -- the coverage numbers below it
    are a floor, and the report has to say so."""
    conn = _conn()
    _run(conn, "r-1", dropped_total=4)
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": None}
    conn.close()


@pytest.fixture
def report_env_with_credential_url():
    """A finding whose evidence points at an exchange whose URL still carries
    a credential in the query string -- `record_exchange`/`record_denial`
    redact at write time, but a hand-inserted row (as this fixture is, and as
    any pre-this-branch row in a real store could be) skips that, which is
    exactly why S12 says redaction has to run again on export."""
    conn = _conn()
    _run(conn, "r-1")
    url = "https://app.acme.test/api/session?access_token=SECRETTOKEN"
    _exchange(conn, "x-1", "r-1", url)
    _finding(conn, run_id="r-1", title="Session token reachable in URL",
            severity="Medium", exchange_ids=["x-1"])
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": None}
    conn.close()


@pytest.fixture
def report_env_with_blobs(tmp_path):
    """One surface whose exemplar exchange's captured request has a query
    parameter and a templated path segment -- both derivable insertion
    points, neither ever probed by this build."""
    conn = _conn()
    _run(conn, "r-1")
    raw = (b"GET /api/orders/1?ref=abc123 HTTP/1.1\r\n"
          b"Host: app.acme.test\r\n"
          b"\r\n")
    store = blobs_mod.BlobStore(tmp_path / "blobs")
    digest, _ = store.put(raw)
    _exchange(conn, "x-1", "r-1",
             "https://app.acme.test/api/orders/1?ref=abc123", req_blob=digest)
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version,"
        " exemplar_exchange_id) VALUES('s-1','e-1','GET','https',"
        "'app.acme.test',443,'/api/orders/{id}','proxy',1,'x-1')")
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": store}
    conn.close()


@pytest.fixture
def report_env_with_long_evidence_chain():
    """One finding, seen in eight distinct observations -- `record_evidence`
    cannot dedupe these (each is a genuinely new exchange, S5's "record_evidence
    accumulates one row per genuinely new observation" behaviour, reviewed in
    Task 5) so this fixture builds the eight rows the honest way: eight real
    exchanges, recorded once each."""
    conn = _conn()
    _run(conn, "r-1")
    exchange_ids = [f"x-{i}" for i in range(8)]
    for i, xid in enumerate(exchange_ids):
        _exchange(conn, xid, "r-1", f"https://app.acme.test/api/item/{i}")
    _finding(conn, run_id="r-1", title="Verbose error on malformed input",
            severity="Low", exchange_ids=exchange_ids)
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": None}
    conn.close()


# --- Step 1's tests, verbatim ------------------------------------------------

def test_the_report_names_the_scope_and_its_hash(report_env):
    out = report.render(**report_env)
    assert "Scope" in out
    assert report_env["config"].scope_include[0] in out


def test_findings_are_grouped_by_severity_highest_first(report_env_with_findings):
    out = report.render(**report_env_with_findings)
    assert out.index("## High") < out.index("## Low")
    # High < Low holds alphabetically too ("H" < "L"), so that assertion
    # alone does not separate severity order from alphabetical order --
    # measured directly in the sweep for row F. Medium < Low does not hold
    # alphabetically ("L" < "M"), so this is the pair that actually pins the
    # ordering this test's name claims to check.
    assert out.index("## Medium") < out.index("## Low")


def test_the_coverage_section_names_checks_that_ran_and_their_verdicts(report_env_with_findings):
    out = report.render(**report_env_with_findings)
    assert "Coverage" in out
    assert "hx.passive.cookie-flags" in out


def test_a_skipped_check_is_rendered_as_skipped_not_omitted(report_env_skipped):
    """The whole point. A check that did not run must appear as `never
    reached`, because omitting it renders as tested and clean."""
    out = report.render(**report_env_skipped)
    assert "skipped" in out.lower()
    assert "budget" in out.lower()


def test_a_run_with_drops_renders_the_coverage_floor(report_env_dropped):
    """S5: a run with drops has coverage numbers that are a FLOOR. The report
    is where an operator reads them, so it is where that must be said."""
    out = report.render(**report_env_dropped)
    assert "floor" in out.lower()


def test_a_run_with_no_drops_says_nothing_about_a_floor(report_env):
    """The separating case. A caveat that is always present is not a caveat."""
    assert "floor" not in report.render(**report_env).lower()


def test_the_limits_section_names_what_this_corpus_cannot_do(report_env):
    """S13 ships no blind-only checks and SAYS SO in the report. A reader must
    not infer coverage this build never had."""
    out = report.render(**report_env)
    assert "Limits" in out
    assert "blind" in out.lower()


def test_urls_are_redacted_on_export(report_env_with_credential_url):
    """S12: redaction runs on export. The blob was redacted at capture; the
    URL column was not necessarily, and the report is the artifact that leaves
    the machine."""
    out = report.render(**report_env_with_credential_url)
    assert "SECRETTOKEN" not in out


def test_a_finding_carries_its_evidence_chain(report_env_with_findings):
    out = report.render(**report_env_with_findings)
    assert "Evidence" in out


def test_derived_insertion_points_are_reported_as_not_probed(report_env_with_blobs):
    """Pre-flight ruling F1. S4 says body and parameter insertion points are
    derived and recorded so the coverage section can say `exists, not probed`.
    Without this the derivation has no consumer in this plan at all."""
    out = report.render(**report_env_with_blobs)
    assert "Insertion points" in out
    assert "None were probed" in out


def test_insertion_points_are_omitted_when_no_blob_store_is_given(report_env):
    """The separating case: `blobs=None` is how a caller says it cannot read
    request bodies, and a section built from nothing would claim zero
    insertion points rather than admitting it did not look."""
    assert "Insertion points" not in report.render(**report_env)


def test_an_engagement_with_no_check_runs_says_it_was_never_scanned(report_env):
    """A report with an empty coverage section is exactly the report S12 calls
    worse than none. It renders, and it says why it is empty."""
    out = report.render(**report_env)
    assert "not been scanned" in out.lower() or "Coverage" in out


# --- the evidence-chain bound -----------------------------------------------
#
# Context carried into this task rather than written in the brief: Task 5's
# review established that `record_evidence` appends one row per genuine
# observation and cannot dedupe across runs, because each run's observation is
# a NEW exchange with a new id -- so a finding seen in fifty runs holds fifty
# evidence rows. `record_evidence`'s own docstring says bounding what gets
# RENDERED is the report's job, not the writer's. These two tests are the
# guard and its separating case, Rule 2 applied to a gap the Step 1 test list
# does not otherwise name.

def test_a_long_evidence_chain_is_capped_and_says_so(report_env_with_long_evidence_chain):
    """8 evidence rows in the store; the render must show fewer and say that
    it did, rather than either printing all 8 or silently dropping the rest
    with no word said."""
    out = report.render(**report_env_with_long_evidence_chain)
    bullets = [line for line in out.splitlines() if line.startswith("- `GET")]
    assert 0 < len(bullets) < 8
    assert "omitted" in out.lower()


def test_a_short_evidence_chain_is_not_reported_as_capped(report_env_with_findings):
    """The separating case: a chain that never approached the bound must not
    claim rows were omitted. A caveat that is always present is not a
    caveat -- the same rule the no-drops test above applies to the floor
    line, applied here to the evidence bound."""
    assert "omitted" not in report.render(**report_env_with_findings).lower()
