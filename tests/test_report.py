"""One Markdown file, and the section that makes it honest.

S12: a report that cannot distinguish "tested, clean" from "never reached" is
worse than no report. Most of these tests are that sentence, applied.

Fix round 1: thirteen findings from the review, F1-F13 below tagged against
their own tests. Every fixture that writes a `check_run` row now also writes
the `surface` row it belongs to and sets `surface_id` on it -- `scan.py`'s
`_open_row` always does (F5's own root cause was a coverage query trusting
`COUNT(*)` where the real writer, and now these fixtures too, always attaches
a surface), and a fixture that skipped that no longer matches what production
ever writes.
"""
import hashlib
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


def _run(conn, run_id="r-1", *, dropped_total=0, started_us=1,
        scope_version_id=None, ended_us=None) -> None:
    conn.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " ended_us, status, dropped_total, scope_version_id)"
        " VALUES(?,'e-1','manual','staging',?,?,'completed',?,?)",
        (run_id, started_us, ended_us, dropped_total, scope_version_id))


def _scope_version(conn, sv_id, *, sha256, effective_from_us, author="james",
                  reason="engagement created", cfg=None) -> None:
    """A row in the append-only scope table.

    `sha256` is passed rather than computed so a test can make it DISAGREE
    with `yaml` -- which is what separates "the report cites the recorded
    hash" from "the report re-hashes whatever config it was handed and
    prints that". The triggers on this table forbid UPDATE and DELETE, so
    every row a test writes is one it must get right on the way in."""
    conn.execute(
        "INSERT INTO scope_version(id, engagement_id, yaml, sha256,"
        " effective_from_us, author, reason) VALUES(?,'e-1',?,?,?,?,?)",
        (sv_id, config_mod.dumps(cfg) if cfg is not None else "scope: {}",
         sha256, effective_from_us, author, reason))


def _digest(cfg) -> str:
    """The sha256 `engagement._record_scope` stores for a config: the hash of
    exactly what `config.dumps` produced. Spelled here the same way, so a
    test can build a scope version that genuinely matches a config."""
    return hashlib.sha256(config_mod.dumps(cfg).encode("utf-8")).hexdigest()


def _surface(conn, surface_id="s-1", *, path_template="/",
            exemplar_exchange_id=None) -> None:
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version,"
        " exemplar_exchange_id) VALUES(?,'e-1','GET','https',"
        "'app.acme.test',443,?,'proxy',1,?)",
        (surface_id, path_template, exemplar_exchange_id))


def _check_run(conn, check_run_id, *, run_id, surface_id, check_id,
               verdict, reason=None) -> None:
    """The same shape `scan.py`'s `_open_row`/`_close_row` always write: a
    `surface_id` on every row, including a skipped one. F5's own defect was
    a coverage query that overcounted because a retested surface produced
    one row per run; a fixture that never set `surface_id` at all would
    have hidden that instead of separating it."""
    conn.execute(
        "INSERT INTO check_run(id, run_id, surface_id, check_id,"
        " check_version, verdict, reason, requests_sent)"
        " VALUES(?,?,?,?,'1',?,?,0)",
        (check_run_id, run_id, surface_id, check_id, verdict, reason))


def _exchange(conn, exchange_id, run_id, url, *, req_blob=None,
             status=200) -> None:
    conn.execute(
        "INSERT INTO exchange(id, run_id, via, outcome, sent_us, method,"
        " url, req_blob, status) VALUES(?,?,'proxy','ok',1,'GET',?,?,?)",
        (exchange_id, run_id, url, req_blob, status))


def _finding(conn, *, run_id, title, severity, exchange_ids,
            check_id=None, description=None, impact=None,
            remediation=None) -> str:
    c = base.Candidate(title=title, issue_type_id=title.lower().replace(" ", "-"),
                       severity=severity, confidence="Firm",
                       insertion=None, exchange_ids=tuple(exchange_ids),
                       description=description, impact=impact,
                       remediation=remediation)
    key = records.dedupe_key(type_=title, issue_type_id=c.issue_type_id,
                             scheme="https", host="app.acme.test",
                             port=443, method="GET", path_template="/",
                             insertion_kind=None, insertion_name=None,
                             scope_level=c.scope_level)
    fid = records.upsert_finding(conn, engagement_id="e-1", candidate=c,
                                 dedupe_key=key, run_id=run_id,
                                 check_id=check_id)
    if exchange_ids:
        records.record_evidence(conn, finding_id=fid,
                                exchange_ids=exchange_ids, at_us=1)
    return fid


def _config(**over) -> config_mod.Config:
    args = dict(name="acme-2026", client="Acme Corp",
               scope_include=["https://app.acme.test/*"])
    args.update(over)
    return config_mod.Config(**args)


@pytest.fixture
def report_env():
    """A real engagement with one completed run that dropped nothing --
    F10: a fixture with NO run at all cannot separate "ran, dropped
    nothing" from "never ran"; `SELECT COUNT(*) FROM run` would render the
    same "no floor line" result as the correct `SUM(dropped_total)` query,
    which is exactly the coincidence that let that mutation pass 14 tests."""
    conn = _conn()
    _run(conn, "r-1", dropped_total=0)
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": None}
    conn.close()


@pytest.fixture
def report_env_no_runs():
    """An engagement created and never run: the separating case for the
    assessment-window sentence, which must not be invented for a store with
    no `run` row to draw it from."""
    conn = _conn()
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": None}
    conn.close()


@pytest.fixture
def report_env_with_findings():
    """A High, a Medium and a Low finding, each with one evidence row, plus
    a `check_run` row for `hx.passive.cookie-flags` on a real surface so the
    coverage section has something named to find. The Medium finding is what
    separates "highest severity first" from "alphabetical": High < Low holds
    under BOTH orderings ("H" before "L" either way), so a two-severity
    fixture cannot tell them apart -- measured directly, sweep row F.
    Medium < Low disagrees: severity order wants Medium first; alphabetical
    order wants Low first ("L" < "M")."""
    conn = _conn()
    _run(conn, "r-1")
    _surface(conn, "s-1")
    _exchange(conn, "x-1", "r-1", "https://app.acme.test/login")
    _exchange(conn, "x-2", "r-1", "https://app.acme.test/")
    _exchange(conn, "x-3", "r-1", "https://app.acme.test/admin")
    _finding(conn, run_id="r-1", title="Reflected XSS in search",
            severity="High", exchange_ids=["x-1"], check_id="hx.test.xss")
    _finding(conn, run_id="r-1", title="Cookie set without HttpOnly",
            severity="Low", exchange_ids=["x-2"],
            check_id="hx.passive.cookie-flags")
    _finding(conn, run_id="r-1", title="Verbose stack trace on error",
            severity="Medium", exchange_ids=["x-3"])
    _check_run(conn, "cr-1", run_id="r-1", surface_id="s-1",
              check_id="hx.passive.cookie-flags", verdict="finding")
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": None}
    conn.close()


@pytest.fixture
def report_env_skipped():
    """A check the budget cut off before it ran, on a real surface -- so
    omitting it from the coverage table would render it as tested rather
    than never reached."""
    conn = _conn()
    _run(conn, "r-1")
    _surface(conn, "s-1")
    _check_run(conn, "cr-1", run_id="r-1", surface_id="s-1",
              check_id="hx.test.timing-probe", verdict="skipped",
              reason="budget")
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
    """A finding whose TITLE, DESCRIPTION, IMPACT and REMEDIATION all name a
    URL carrying a credential, plus a `check_run.reason` built the same way
    `hx.scan` builds one -- `f"{type(exc).__name__}: {exc}"`, quoting the
    same URL. F1: `records.redact_url` used to run at exactly one site (the
    evidence URL); this fixture is the one render that exercises all five
    vectors the review measured leaking at once."""
    conn = _conn()
    _run(conn, "r-1")
    _surface(conn, "s-1")
    url = "https://admin:hunter2@app.acme.test/reset?access_token=SECRETTOKEN"
    _exchange(conn, "x-1", "r-1", url)
    _finding(conn, run_id="r-1",
            title=f"Password reset link leaks a token: {url}",
            severity="Medium", exchange_ids=["x-1"],
            description=f"Seen at {url} during manual review.",
            impact=f"An attacker with {url} can reset the account.",
            remediation=f"Stop emailing {url} with the token inline.")
    _check_run(conn, "cr-1", run_id="r-1", surface_id="s-1",
              check_id="hx.test.stack-trace", verdict="error",
              reason=f"CorruptBlob: fetching {url} failed")
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
    _surface(conn, "s-1", path_template="/api/orders/{id}",
            exemplar_exchange_id="x-1")
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": store}
    conn.close()


@pytest.fixture
def report_env_with_surface_but_no_blobstore():
    """A surface with a real captured request (a `req_blob` digest), but
    `blobs=None` -- the caller-cannot-read-request-bodies case. F8: without
    a fixture like this, `blobs is not None` is only ever exercised by
    fixtures with zero surfaces at all, so a bare `except Exception` around
    `blobs.get` silently absorbs the `AttributeError` from `None.get(...)`
    and the guard's own removal is unobservable."""
    conn = _conn()
    _run(conn, "r-1")
    _exchange(conn, "x-1", "r-1",
             "https://app.acme.test/api/orders/1?ref=abc123",
             req_blob="ab" * 32)
    _surface(conn, "s-1", path_template="/api/orders/{id}",
            exemplar_exchange_id="x-1")
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": None}
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


@pytest.fixture
def report_env_with_unresolvable_evidence():
    """8 evidence rows for one finding: 1 resolves to a real exchange, 7 do
    not -- `evidence.exchange_id` is nullable and the `LEFT JOIN` in
    `_evidence` exists to anticipate exactly this (a note/ref-only row).
    `record_evidence` never writes such a row today, so this is built
    directly, the same way the review measured it: F6, "rendered + omitted
    != total"."""
    conn = _conn()
    _run(conn, "r-1")
    _exchange(conn, "x-0", "r-1", "https://app.acme.test/api/item/0")
    fid = _finding(conn, run_id="r-1",
                  title="Error detail varies by unresolved evidence",
                  severity="Low", exchange_ids=["x-0"])
    # `_finding` already recorded seq 0 (x-0, resolvable) via the normal
    # `record_evidence` path; seq 1-7 are the unresolvable rows, built
    # directly since no writer produces them today.
    for i in range(1, 8):
        conn.execute(
            "INSERT INTO evidence(id, finding_id, seq, role, kind,"
            " exchange_id, note, captured_us) VALUES(?,?,?,'note','note',"
            "NULL,'could not resolve',1)", (f"ev-{i}", fid, i))
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": None}
    conn.close()


@pytest.fixture
def report_env_scanned_clean():
    """A real scan ran (one `check_run` row, `verdict='clean'`) and found
    nothing. F4's separating case: "None recorded" here must NOT carry the
    "not been scanned yet" qualifier that an engagement with zero
    `check_run` rows gets -- a caveat that fires whether or not it is true
    is not a caveat."""
    conn = _conn()
    _run(conn, "r-1")
    _surface(conn, "s-1")
    _check_run(conn, "cr-1", run_id="r-1", surface_id="s-1",
              check_id="hx.passive.cookie-flags", verdict="clean")
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": None}
    conn.close()


@pytest.fixture
def report_env_with_fixed_finding():
    """A finding found in run 1 (`observed=True`), retested clean in run 2
    (`observed=False`) -- the exact scenario Tasks 5 and 6 spent three fix
    rounds making `finding_observation.observed` correct for. F9: the report
    must say the finding is gone as of the latest run, not print it
    identically to a live one."""
    conn = _conn()
    _run(conn, "r-1", started_us=1)
    _run(conn, "r-2", started_us=2)
    _exchange(conn, "x-1", "r-1", "https://app.acme.test/old-endpoint")
    fid = _finding(conn, run_id="r-1", title="XSS since patched",
                  severity="High", exchange_ids=["x-1"])
    records.record_observation(conn, finding_id=fid, run_id="r-1",
                               observed=True, exchange_id="x-1",
                               severity_at="High", confidence_at="Firm",
                               at_us=1)
    records.record_observation(conn, finding_id=fid, run_id="r-2",
                               observed=False, exchange_id=None,
                               severity_at="High", confidence_at="Firm",
                               at_us=2)
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": None}
    conn.close()


@pytest.fixture
def report_env_with_reconfirmed_finding():
    """The same two-run shape as `report_env_with_fixed_finding`, except run
    2 observes the finding AGAIN (`observed=True`) -- the separating case:
    a finding actually still live in the latest run must not carry a
    "appears fixed" marker."""
    conn = _conn()
    _run(conn, "r-1", started_us=1)
    _run(conn, "r-2", started_us=2)
    _exchange(conn, "x-1", "r-1", "https://app.acme.test/still-broken")
    fid = _finding(conn, run_id="r-1", title="Persistent header issue",
                  severity="High", exchange_ids=["x-1"])
    records.record_observation(conn, finding_id=fid, run_id="r-1",
                               observed=True, exchange_id="x-1",
                               severity_at="High", confidence_at="Firm",
                               at_us=1)
    records.record_observation(conn, finding_id=fid, run_id="r-2",
                               observed=True, exchange_id="x-1",
                               severity_at="High", confidence_at="Firm",
                               at_us=2)
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": None}
    conn.close()


@pytest.fixture
def report_env_fixed_then_a_skipped_run():
    """R2 (fix round 2): run 1 finds it, run 2 retests clean (fixed), run 3
    is LATER (`started_us=3`) but its check was skipped for this surface --
    no `finding_observation` row for run 3 at all, the same shape a real
    `skipped`/`error`/never-in-this-run's-checks run leaves. `_latest_observed`
    must still answer off run 2 (correctly: `False`), but the marker text
    must not claim "the most recent run" -- run 3 IS the most recent run of
    the engagement, and it never tested this finding. The old wording was
    literally false of this exact scenario."""
    conn = _conn()
    _run(conn, "r-1", started_us=1)
    _run(conn, "r-2", started_us=2)
    _run(conn, "r-3", started_us=3)
    _exchange(conn, "x-1", "r-1", "https://app.acme.test/old-endpoint")
    fid = _finding(conn, run_id="r-1", title="XSS since patched, then skipped",
                  severity="High", exchange_ids=["x-1"])
    records.record_observation(conn, finding_id=fid, run_id="r-1",
                               observed=True, exchange_id="x-1",
                               severity_at="High", confidence_at="Firm",
                               at_us=1)
    records.record_observation(conn, finding_id=fid, run_id="r-2",
                               observed=False, exchange_id=None,
                               severity_at="High", confidence_at="Firm",
                               at_us=2)
    # No finding_observation row for r-3 -- the check never tested this
    # surface that run, even though r-3 is chronologically the latest run.
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": None}
    conn.close()


# --- Step 1's tests, verbatim (bar F3's tautology and F4's qualifier) -------

def test_the_report_names_the_scope_and_its_hash(report_env):
    """F4 (fix round B): THE HASH USED TO BE IN THIS TEST'S NAME ONLY. It
    asserted that the word "Scope" and the pattern appeared, and passed
    against a report that cited no hash at all, no scope version, no dates
    and no authorization record -- which is how S12's provenance sentence
    survived nine reviews unimplemented.

    Here the store holds a scope version whose `sha256` genuinely is the
    hash of this config (`_digest` spells it the way
    `engagement._record_scope` does), so the report may say so; the
    divergence case below is the separating one."""
    cfg = report_env["config"]
    _scope_version(report_env["conn"], "sv-1", sha256=_digest(cfg),
                  effective_from_us=1, cfg=cfg)
    out = report.render(**report_env)
    assert "Scope of record" in out
    assert cfg.scope_include[0] in out
    assert _digest(cfg) in out
    assert "verified, not assumed" in out


def test_the_scope_hash_is_the_recorded_one_not_a_hash_of_todays_config(report_env):
    """The separating case, and the one that pins WHICH hash is rendered.

    `render` takes `config` as a free parameter, so a report that simply
    re-hashed whatever it was handed would print a hash on every render and
    look identical to one that read the store. Here the recorded row's
    `sha256` deliberately does not match the config, which is the shape a
    hand-edited `config.yaml` has (`engagement.open_` refuses to open such a
    store, so through `hx report` it cannot happen -- but `render` is a
    public function and the claim above the patterns has to be true of every
    caller). The recorded hash must appear, and the report must say the
    patterns are not the scope of record rather than quietly presenting
    them as it."""
    recorded = "de" * 32
    _scope_version(report_env["conn"], "sv-1", sha256=recorded,
                  effective_from_us=1)
    out = report.render(**report_env)
    assert recorded in out
    assert "NOT the scope of record" in out
    assert "verified, not assumed" not in out


def test_an_engagement_with_no_scope_version_says_the_patterns_are_unverified(report_env):
    """The third case: nothing recorded at all. The patterns are still
    rendered -- a report with no scope in it is useless -- but the sentence
    above them must not let a reader take today's config for the boundary
    that was in force when the traffic was captured."""
    out = report.render(**report_env)
    assert "No scope version is recorded" in out
    assert report_env["config"].scope_include[0] in out
    assert "verified, not assumed" not in out


def test_every_scope_version_is_rendered_not_only_the_latest(report_env):
    """S5: "The one query that matters under dispute is 'what was in scope
    when request X was issued', and it must be answerable." A second row in
    this append-only table means the boundary MOVED mid-engagement, and
    rendering only the newest as though it had always been the boundary
    answers that query wrongly and silently.

    Two versions, two runs, one stamped to each -- so the `Runs` column is
    the part that makes the table answer the query at the grain the store
    records it."""
    conn = report_env["conn"]
    _scope_version(conn, "sv-1", sha256="a" * 64, effective_from_us=1,
                  author="james", reason="engagement created")
    _scope_version(conn, "sv-2", sha256="b" * 64, effective_from_us=2,
                  author="dana", reason="client added the staging host")
    conn.execute("UPDATE run SET scope_version_id='sv-1' WHERE id='r-1'")
    _run(conn, "r-2", started_us=3, scope_version_id="sv-2")
    out = report.render(**report_env)
    assert "a" * 64 in out
    assert "b" * 64 in out
    assert out.index("a" * 64) < out.index("b" * 64)
    assert "client added the staging host" in out
    assert "engagement created" in out
    assert "2 scope version(s) are on file" in out
    # One run under each, which is the datum `run.scope_version_id` carries
    # and nothing rendered before this fix.
    rows = [l for l in out.splitlines() if l.startswith("| 1970-01-01")]
    assert len(rows) == 2
    assert all("| 1 |" in row for row in rows), rows


def test_a_run_stamped_with_no_scope_version_is_called_out(report_env):
    """`run.scope_version_id` is nullable and every fixture in this file
    leaves it NULL. A table of scope versions with a `Runs` column that adds
    up to fewer runs than the engagement has is a table that quietly loses
    them."""
    _scope_version(report_env["conn"], "sv-1", sha256="a" * 64,
                  effective_from_us=1)
    out = report.render(**report_env)
    assert "1 run(s) carry no `scope_version_id`" in out
    # And it must say WHICH absence a `Runs` count of 0 is. `run.open_run`
    # never writes `scope_version_id` -- no code path in this repository
    # does -- so 0 is what every store this build produces will show, beside
    # a paragraph two above saying how many runs were recorded. Left
    # unexplained that reads as a contradiction in a client document.
    assert "Nothing in this build writes that link" in out


def test_the_report_dates_the_engagement_and_its_run_window(report_env):
    """`engagement.created_us` was SELECTed and dropped on the floor, and no
    date of any kind reached the document. A client deliverable that cannot
    say when the assessment happened cannot be read against the application
    it describes."""
    conn = report_env["conn"]
    conn.execute("UPDATE engagement SET created_us=1756000000000000"
                 " WHERE id='e-1'")
    conn.execute("UPDATE run SET started_us=1756000100000000,"
                 " ended_us=1756003700000000 WHERE id='r-1'")
    out = report.render(**report_env)
    assert "Engagement opened 2025-08-24 01:46:40Z" in out
    assert "1 run(s) recorded" in out
    assert "earliest starting 2025-08-24 01:48:20Z" in out
    assert "latest ending 2025-08-24 02:48:20Z" in out


def test_an_engagement_with_no_runs_says_nothing_was_observed(report_env_no_runs):
    """The separating case for the window sentence: an engagement that has
    never run has no window, and rendering one would be inventing it."""
    out = report.render(**report_env_no_runs)
    assert "No run has been recorded" in out
    assert "run(s) recorded, the earliest" not in out


def test_the_absent_authorization_record_is_stated_not_omitted(report_env):
    """S12: "The report cites `scope_version.sha256` and the `authorization`
    record in force, so what you were permitted to touch is part of the
    deliverable." Nothing in this repository writes an `authorization` row
    -- the table is declared in `schema.sql`, named in `db.py`'s
    expected-table set, and written by no code path in `src/`, `extension/`
    or `tests/`. A deliverable that simply left the section out would read
    as though a record existed and had not been included."""
    out = report.render(**report_env)
    assert "### Authorization" in out
    assert "No authorization record is on file" in out
    assert "Read nothing above as evidence that testing was authorised" in out


def test_an_authorization_record_on_file_is_rendered(report_env):
    """The separating case. No writer exists yet, so the row is built
    directly -- the same way this file builds the note/ref-only `evidence`
    row the schema allows and no writer produces. When a later plan adds a
    writer, this is the assertion it has to satisfy."""
    report_env["conn"].execute(
        "INSERT INTO authorization(id, engagement_id, doc_blob, doc_sha256,"
        " signatory, valid_from_us, valid_to_us, scope_sha256)"
        " VALUES('auth-1','e-1','blob-1',?,'Dana Reyes, CISO',"
        "1756000000000000,1758000000000000,?)", ("c" * 64, "a" * 64))
    out = report.render(**report_env)
    assert "No authorization record is on file" not in out
    assert "Dana Reyes, CISO" in out
    assert "c" * 64 in out
    assert "2025-08-24 01:46:40Z" in out


def test_a_credential_pasted_into_a_scope_pattern_is_redacted(report_env):
    """R1 (fix round 2): F1's own fix missed the Scope section -- an
    operator-authored `scope.include`/`scope.exclude` pattern reached the
    export raw, the one place left where a credential survived. `_redact`
    now wraps every pattern; `test_the_report_names_the_scope_and_its_hash`
    above is the separating case for the ordinary pattern (no credential in
    it, `_redact` is identity)."""
    env = dict(report_env)
    env["config"] = _config(
        scope_include=["https://admin:hunter2@app.acme.test/*"],
        scope_exclude=["https://svc:s3cr3t@internal.acme.test/*"])
    out = report.render(**env)
    assert "hunter2" not in out
    assert "s3cr3t" not in out
    assert "app.acme.test" in out


def test_findings_are_grouped_by_severity_highest_first(report_env_with_findings):
    out = report.render(**report_env_with_findings)
    assert out.index("### High") < out.index("### Low")
    # High < Low holds alphabetically too ("H" < "L"), so that assertion
    # alone does not separate severity order from alphabetical order --
    # measured directly in the sweep for row F. Medium < Low does not hold
    # alphabetically ("L" < "M"), so this is the pair that actually pins the
    # ordering this test's name claims to check.
    assert out.index("### Medium") < out.index("### Low")


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
    """The separating case. A caveat that is always present is not a
    caveat. F10: `report_env` now has a real run (`dropped_total=0`) rather
    than none at all, so a mutation keying the floor line on `COUNT(*) FROM
    run` (any run at all) rather than `SUM(dropped_total)` now has something
    to disagree with."""
    assert "floor" not in report.render(**report_env).lower()


def test_the_limits_section_names_what_this_corpus_cannot_do(report_env):
    """S13 ships no blind-only checks and SAYS SO in the report. A reader must
    not infer coverage this build never had."""
    out = report.render(**report_env)
    assert "Limits" in out
    assert "blind" in out.lower()


def test_the_limits_section_says_a_fix_cannot_be_shown_by_re_browsing(
        report_env_with_findings):
    """Every check this build ships is passive: `scan._exchanges_for` reads
    an engagement's WHOLE captured history for a surface, not only its
    newest traffic, so one recorded bad response keeps a finding live no
    matter how much clean traffic follows it. `report_env_with_findings`
    writes findings but no `finding_observation` row at all, which is the
    point -- this bullet is a build fact, unconditional on any run having
    retested anything, not a consequence of what a particular scan
    observed."""
    out = report.render(**report_env_with_findings)
    assert "Limits" in out
    assert "cannot be shown as fixed by re-browsing" in out


def test_urls_are_redacted_on_export(report_env_with_credential_url):
    """S12: redaction runs on export. The blob was redacted at capture; the
    URL column was not necessarily, and the report is the artifact that leaves
    the machine."""
    out = report.render(**report_env_with_credential_url)
    assert "SECRETTOKEN" not in out
    assert "hunter2" not in out


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
    """F3: the review's own read of this test -- `... or "Coverage" in out`
    -- can never fail, because `## Coverage` is emitted unconditionally.
    Deleting the entire "not been scanned" paragraph left 14 passing.
    Replaced with the assertion that is actually conditional -- and, per a
    gap this sweep found in fix round 1 itself, scoped to the Coverage
    section specifically: F4's own qualifier on "None recorded" ALSO
    contains the substring "not been scanned", so a whole-document search
    stayed green even with this paragraph deleted, once F4 existed beside
    it. Measured, not assumed -- see the fix-1 report."""
    out = report.render(**report_env)
    coverage_section = out[out.index("## Coverage"):]
    assert "not been scanned" in coverage_section.lower()


# --- F12: a live finding must not be rendered wearing stale prose ----------

def test_a_partly_remediated_finding_renders_the_current_prose_not_run_ones():
    """F12 (fix round B), measured end to end in the artifact that matters.

    `records.upsert_finding`'s `ON CONFLICT ... DO UPDATE SET` refreshed
    `severity` and `confidence` and not `title`, `description`, `impact`,
    `remediation` or `cwe` -- so a re-scan updated how bad a finding was and
    never what it SAID. After D1 of the fix-round-A re-review a cookie's
    identity is the COOKIE and its missing flags are deliberately not in the
    key, which is right and is exactly what makes the stale prose reachable:
    one finding, two observations, and run 1's title after the client set
    two of the three flags.

    Built the way `hx.scan._write_finding` builds it -- one dedupe key,
    fixed across both runs, and the candidate carrying that run's own state
    -- because the key is what makes the two writes collide.
    """
    conn = _conn()
    _run(conn, "r-1", started_us=1)
    _run(conn, "r-2", started_us=2)
    _exchange(conn, "x-1", "r-1", "https://app.acme.test/login")
    _exchange(conn, "x-2", "r-2", "https://app.acme.test/login")
    key = records.dedupe_key(
        type_="hx.passive.cookie-flags", issue_type_id="cookie-session-flags",
        scheme="https", host="app.acme.test", port=443, method="GET",
        path_template="/", insertion_kind=None, insertion_name=None,
        scope_level="host")

    def write(run_id, exchange_id, missing, severity, cwe):
        flags = ", ".join(missing)
        c = base.Candidate(
            title=f"Cookie session set without {flags}",
            issue_type_id="cookie-session-flags", severity=severity,
            confidence="Certain", insertion=None, scope_level="host",
            exchange_ids=(exchange_id,), cwe=cwe,
            description=f"The response set `session` without {flags}.",
            impact=f"`session` is exposed because it lacks {flags}.",
            remediation=f"Set {flags} on `session`.")
        fid = records.upsert_finding(conn, engagement_id="e-1", candidate=c,
                                     dedupe_key=key, run_id=run_id,
                                     check_id="hx.passive.cookie-flags")
        records.record_evidence(conn, finding_id=fid,
                                exchange_ids=(exchange_id,), at_us=1)
        records.record_observation(conn, finding_id=fid, run_id=run_id,
                                   observed=True, exchange_id=exchange_id,
                                   severity_at=severity,
                                   confidence_at="Certain", at_us=1)
        return fid

    first = write("r-1", "x-1", ["HttpOnly", "SameSite", "Secure"],
                  "Medium", "CWE-1004")
    second = write("r-2", "x-2", ["SameSite"], "Low", "CWE-614")
    assert first == second, "the cookie is the identity: this must be ONE finding"

    counts = conn.execute(
        "SELECT (SELECT COUNT(*) FROM finding),"
        " (SELECT COUNT(*) FROM finding_observation)").fetchone()
    out = report.render(conn=conn, engagement_id="e-1", config=_config())
    conn.close()

    assert counts == (1, 2), "one finding, two observations"
    # Every prose column, not just the title: each is current state and each
    # was frozen at run 1.
    assert "Cookie session set without SameSite" in out
    assert "Cookie session set without HttpOnly, SameSite, Secure" not in out
    assert "The response set `session` without SameSite." in out
    assert "`session` is exposed because it lacks SameSite." in out
    assert "Set SameSite on `session`." in out
    assert "HttpOnly" not in out
    # `cwe` is computed from the same current state `severity` is
    # (`cookie_flags`: "CWE-1004" if HttpOnly is missing else "CWE-614"), so
    # leaving it behind pairs a refreshed severity with a stale
    # classification on one row.
    assert "CWE-614" in out
    assert "CWE-1004" not in out
    assert "### Low" in out
    assert "### Medium" not in out


# --- F8: an aborted run must never render as a complete one ----------------

def _unfinished_run(conn, run_id, *, status, stop_reason=None, started_us=1,
                   kind="scan") -> None:
    """A run that stopped. `run.status` is constrained to
    `running|completed|aborted|killed|error` and every other fixture in this
    file writes `completed`, which is why nothing here could tell a partial
    pass from a whole one."""
    conn.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status, stop_reason, dropped_total)"
        " VALUES(?,'e-1',?,'staging',?,?,?,0)",
        (run_id, kind, started_us, status, stop_reason))


def test_a_completed_run_renders_no_partial_warning(report_env_scanned_clean):
    """The separating case, and the one that makes the rest a caveat rather
    than boilerplate: a scan that ran to completion must say nothing about
    having stopped."""
    out = report.render(**report_env_scanned_clean)
    assert "did not finish" not in out
    assert "These numbers are partial" not in out


@pytest.mark.parametrize("status", ["aborted", "killed", "error", "running"])
def test_a_run_that_did_not_complete_is_named_and_marks_coverage_partial(status):
    """S5, of `run`: "an aborted run must never render as a clean one, and
    neither must one that merely STOPPED BEING UPDATED: a run left `running`
    with a stale heartbeat_us is a run whose harness died, and it resolves
    to `error`, not `completed`." Nothing in this module read `run.status`
    or `run.stop_reason` at all, so a scan stopped by Ctrl-C, by a
    `sqlite3.Error` through `cli.scan`'s `except`-less `try`/`finally`, or
    by a stale-heartbeat reap rendered its partial coverage byte-identically
    to a complete pass.

    All four non-`completed` values, `running` included: a run still in
    flight while the report renders has produced partial coverage too."""
    conn = _conn()
    _unfinished_run(conn, "r-1", status=status,
                   stop_reason="KeyboardInterrupt")
    _surface(conn, "s-1")
    _check_run(conn, "cr-1", run_id="r-1", surface_id="s-1",
              check_id="hx.passive.cookie-flags", verdict="clean")
    out = report.render(conn=conn, engagement_id="e-1", config=_config())
    conn.close()

    assert "1 of those runs did not finish" in out
    assert f"ended `{status}`" in out
    assert "run `r-1`" in out
    assert "KeyboardInterrupt" in out
    coverage = out[out.index("## Coverage"):]
    assert "**These numbers are partial.**" in coverage


def test_a_stopped_run_with_no_stop_reason_says_that_rather_than_nothing():
    """`run.stop_reason` is nullable and a reaped run may carry none. The
    line must still exist and must not silently render as though a reason
    had been given."""
    conn = _conn()
    _unfinished_run(conn, "r-1", status="killed", stop_reason=None)
    out = report.render(conn=conn, engagement_id="e-1", config=_config())
    conn.close()
    assert "ended `killed` and recorded no stop reason" in out


def test_a_credential_in_a_stop_reason_is_redacted():
    """`hx.scan.run` writes `stop_reason` as
    `f"scan.run raised: {type(exc).__name__}: {exc}"` -- an exception message
    that can quote a request target, the same construction the coverage
    `reason` cell carries. It is a newly rendered free-text field, so it
    goes through the choke point like every other one."""
    conn = _conn()
    _unfinished_run(
        conn, "r-1", status="error",
        stop_reason="scan.run raised: OSError: GET "
                    "https://admin:hunter2@app.acme.test/x?access_token=SECRETTOKEN")
    out = report.render(conn=conn, engagement_id="e-1", config=_config())
    conn.close()
    assert "hunter2" not in out
    assert "SECRETTOKEN" not in out
    assert "scan.run raised: OSError" in out


# --- F2: the coverage section can show what was never reached --------------

@pytest.fixture
def report_env_browsed_after_the_scan():
    """The everyday trigger, in four surfaces: browse, scan, browse more,
    report. `s-0` was scanned; `/orders`, `/orders/{id}` and `/profile` were
    captured after the scan and no check has ever looked at them. Before F2
    the whole engagement rendered as one `clean 1` row with nothing said
    about the other three."""
    conn = _conn()
    _run(conn, "r-1")
    _surface(conn, "s-0", path_template="/")
    _surface(conn, "s-1", path_template="/orders")
    _surface(conn, "s-2", path_template="/orders/{id}")
    _surface(conn, "s-3", path_template="/profile")
    _check_run(conn, "cr-1", run_id="r-1", surface_id="s-0",
              check_id="hx.passive.cookie-flags", verdict="clean")
    yield {"conn": conn, "engagement_id": "e-1", "config": _config(),
          "blobs": None}
    conn.close()


def test_coverage_states_how_many_surfaces_were_captured_and_how_many_tested(
        report_env_browsed_after_the_scan):
    """1 of F2's three parts: the DENOMINATOR. `COUNT(DISTINCT surface_id)`
    with nothing to divide it by cannot answer "what did you not test?" --
    four `clean 1` rows read identically whether the engagement holds one
    surface or a hundred."""
    out = report.render(**report_env_browsed_after_the_scan)
    assert "captured **4 surface(s)**" in out
    assert "**1** had at least one check return a verdict" in out
    assert "**3** had none" in out


def test_coverage_names_the_surfaces_no_check_ever_answered_for(
        report_env_browsed_after_the_scan):
    """2 of F2's three parts: the ACTIONABLE SET, by name. `method` +
    `path_template` is the surface's readable identity -- the pair
    `_insertion_coverage` selects and the pair `surface`'s own UNIQUE
    constraint builds identity from."""
    out = report.render(**report_env_browsed_after_the_scan)
    coverage = out[out.index("## Coverage"):]
    assert "**Never tested.**" in coverage
    assert "`GET /orders`" in coverage
    assert "`GET /orders/{id}`" in coverage
    assert "`GET /profile`" in coverage
    # The separating half: the surface that WAS answered for must not be in
    # the list, or "never tested" means nothing.
    never = coverage[coverage.index("**Never tested.**"):]
    assert "`GET /`" not in never


def test_a_fully_covered_engagement_renders_no_never_tested_list(
        report_env_scanned_clean):
    """The separating case. A caveat that is always present is not a
    caveat: one surface, one check, one `clean` verdict, nothing left."""
    out = report.render(**report_env_scanned_clean)
    assert "captured **1 surface(s)**" in out
    assert "**1** had at least one check return a verdict" in out
    assert "**0** had none" in out
    assert "Never tested" not in out


def test_the_prose_above_the_coverage_table_does_not_promise_what_it_omits(
        report_env_browsed_after_the_scan):
    """3 of F2's three parts. The old sentence -- "A surface absent from
    this table was **never reached** — which is not the same as clean" --
    could not be checked by a reader, because no surface was ever IN the
    table. Whatever the table renders, the sentence above it has to be true
    of it."""
    out = report.render(**report_env_browsed_after_the_scan)
    assert "A surface absent from this table" not in out
    assert "This table COUNTS surfaces and does not name them" in out


def test_a_surface_whose_only_check_was_skipped_counts_as_never_tested(
        report_env_skipped):
    """S12 in the direction that matters. A `skipped` row exists to record
    that a check did NOT run -- `hx.scan._skip_rest` writes it when a budget
    cuts the scan off -- and `pending` is written before a check runs so
    that "a crash leaves evidence that the surface was never reached" (S5,
    verbatim). Counting either as coverage reads a row that records a gap as
    though it recorded an answer.

    The row still appears in the table with its reason: the two statements
    are not in conflict, and a reader needs both."""
    out = report.render(**report_env_skipped)
    assert "**0** had at least one check return a verdict" in out
    assert "**1** had none" in out
    assert "`GET /`" in out[out.index("**Never tested.**"):]
    assert "budget" in out.lower()


def test_a_surface_whose_check_errored_is_not_listed_as_never_reached(
        report_env_with_credential_url):
    """The separating case for `_ANSWERED`. An `error` verdict means the
    check REACHED the surface and raised -- a failure to answer, not a
    failure to arrive -- and the row renders as `error` where a reader can
    see no clean answer was obtained. Filing it under "never reached" would
    be a different untruth from the one F2 fixes."""
    out = report.render(**report_env_with_credential_url)
    assert "**1** had at least one check return a verdict" in out
    assert "Never tested" not in out


def test_the_never_tested_list_is_capped_and_says_by_how_much():
    """`_findings` caps the evidence chain and STATES the cap; a list of
    surfaces a client is meant to act on gets the same treatment and never a
    silent truncation. 25 untested surfaces, 20 named, 5 accounted for."""
    conn = _conn()
    _run(conn, "r-1")
    for i in range(25):
        _surface(conn, f"s-{i:02d}", path_template=f"/page/{i:02d}")
    out = report.render(conn=conn, engagement_id="e-1", config=_config())
    conn.close()
    listed = [l for l in out.splitlines() if l.startswith("- `GET /page/")]
    assert len(listed) == 20
    assert "5 further surface(s) omitted" in out
    assert "capped at the first 20 of 25" in out


def test_two_surfaces_failing_for_different_reasons_stay_one_coverage_row():
    """CARRIED FROM FIX ROUND A, and it lands on this function. F6 of that
    round made a passive check's `inconclusive` reason NAME the unreadable
    exchange ids (`_http._detail`), so the old
    `GROUP BY check_id, verdict, reason` stopped grouping: two surfaces
    failing the same way for different exchanges became two rows, and a
    hundred became a hundred. `check_id` and `verdict` are controlled
    vocabularies, so grouping on them alone bounds the table however much
    free text the reason carries -- and the reason stays actionable by being
    carried into the row, commonest first, capped and counted."""
    conn = _conn()
    _run(conn, "r-1")
    for i in range(3):
        _surface(conn, f"s-{i}", path_template=f"/page/{i}")
        _check_run(conn, f"cr-{i}", run_id="r-1", surface_id=f"s-{i}",
                  check_id="hx.passive.stack-trace", verdict="inconclusive",
                  reason=f"x-{i}: outcome=timeout")
    out = report.render(conn=conn, engagement_id="e-1", config=_config())
    conn.close()
    rows = [l for l in out.splitlines()
            if l.startswith("| `hx.passive.stack-trace`")]
    assert len(rows) == 1, rows
    assert "| inconclusive | 3 |" in rows[0]
    # Two reasons named, the third counted -- never dropped in silence.
    assert "x-0: outcome=timeout" in rows[0]
    assert "x-1: outcome=timeout" in rows[0]
    assert "and 1 further distinct reason(s)" in rows[0]


def test_one_reason_shared_by_every_surface_is_printed_once(report_env_skipped):
    """The separating case for the reason cap: a single distinct reason must
    print plainly, with no "further distinct reason(s)" tail."""
    out = report.render(**report_env_skipped)
    row = [l for l in out.splitlines()
           if l.startswith("| `hx.test.timing-probe`")]
    assert len(row) == 1
    assert "| skipped | 1 | budget |" in row[0]
    assert "further distinct reason" not in row[0]


# --- F5: the no-active-checks prose is derived from the corpus, not typed ---

class _FakeActiveCheck:
    """An `active_safe` entry shaped exactly like a registry entry.

    Only `id` and `klass` are read by `report`; `version` and
    `insertion_kinds` are here so this is a check by the same description
    `registry.validate` uses, not a stub that happens to satisfy one caller.
    It is NOT put through `registry.validate` (it implements no hook), which
    is deliberate: the point is to make the REPORT face a corpus containing
    an active check, and a check that cannot run would still be a check the
    Limits section must not deny the existence of.
    """
    id = "hx.active_safe.reflected-input"
    version = "1"
    klass = "active_safe"
    insertion_kinds = frozenset({"query"})


def test_the_shipped_corpus_is_all_passive_and_the_prose_says_so(
        report_env_with_blobs):
    """The separating case, and the reason F5 survived nine reviews: every
    one of these sentences is TRUE of the build as it stands. What was wrong
    is that none of them was derived from it."""
    out = report.render(**report_env_with_blobs)
    assert "**None were probed** — this build ships no active checks." in out
    assert "no request carrying a payload was ever issued" in out
    assert "Every check in this build is passive" in out


def test_registering_an_active_check_falsifies_none_of_the_limits_prose(
        report_env_with_blobs, monkeypatch):
    """THE ACTUAL DELIVERABLE OF F5. Plan 6's first active check is what
    makes the three hardcoded sentences false, and before this test nothing
    reddened when it did -- a client would be told no payload was ever
    issued while `check_run.requests_sent` said otherwise, and the
    passive-retest disclosure (true only while every shipped check is
    passive) would decay in the same silence.

    `registry.CHECKS` is patched rather than a real check being registered,
    because registering one is Plan 6's job and this test must fail TODAY if
    the prose stops being derived. All three sentences are asserted absent
    and their replacements asserted present: a fix that deleted the
    sentences instead of deriving them would pass the absence half alone."""
    monkeypatch.setattr(report.registry, "CHECKS",
                        tuple(report.registry.CHECKS) + (_FakeActiveCheck(),))
    out = report.render(**report_env_with_blobs)

    assert "this build ships no active checks" not in out
    assert "no request carrying a payload was ever issued" not in out
    assert "Every check in this build is passive" not in out

    # And it must say what IS true instead, naming the check by id in each
    # of the three places -- Insertion points, and both Limits bullets.
    assert out.count("`hx.active_safe.reflected-input`") == 3
    assert "active check(s) ship in this build" in out
    assert "none of them can reach a request body" in out
    assert "are not limited this way" in out


# --- F1: redaction reaches every field that can carry a URL -----------------

def test_a_credential_in_the_client_or_engagement_name_is_redacted(report_env):
    """F10 (fix round B): `engagement.client` is the document's TITLE and
    `engagement.name` is the line under it, and neither passed through
    `_redact`. Standing ruling R1 -- operator-authored text is not exempt --
    already made this a defect for scope patterns; `hx new --client` takes
    its string off the same command line. The review called `client` "the
    last free-text rendered field"; `name` was raw beside it, so both are
    asserted here.

    The host survives redaction (only the userinfo is cut), which is what
    separates "redacted" from "the title vanished"."""
    report_env["conn"].execute(
        "UPDATE engagement SET client=?, name=? WHERE id='e-1'",
        ("https://admin:hunter2@acme.test/portal — Acme Corp",
         "acme-2026 https://svc:s3cr3t@ci.acme.test/job"))
    out = report.render(**report_env)
    assert "hunter2" not in out
    assert "s3cr3t" not in out
    assert "acme.test" in out
    assert "Acme Corp" in out


def test_a_credential_url_is_redacted_from_every_field_it_reaches(report_env_with_credential_url):
    """The five-vector render the review measured leaking at once: title,
    description, impact, remediation, and the coverage table's `reason`
    cell. `redact_url` used to run at exactly one site (the evidence URL);
    this asserts none of the other four still leak."""
    out = report.render(**report_env_with_credential_url)
    assert "SECRETTOKEN" not in out
    assert "hunter2" not in out
    # And the fields must still be THERE, redacted rather than dropped --
    # a finding whose title vanished would be a different bug.
    assert "Password reset link leaks a token" in out
    assert "CorruptBlob: fetching" in out


# --- F4: an unscanned engagement's "None recorded" is qualified ------------

def test_none_recorded_is_qualified_when_the_engagement_was_never_scanned(report_env):
    out = report.render(**report_env)
    findings_section = out[out.index("## Findings"):out.index("## Coverage")]
    assert "None recorded" in findings_section
    assert "scanned" in findings_section.lower()


def test_none_recorded_is_unqualified_once_a_clean_scan_has_run(report_env_scanned_clean):
    """The separating case: a real scan that found nothing must not carry
    the "not scanned yet" qualifier -- that would be false of it."""
    out = report.render(**report_env_scanned_clean)
    findings_section = out[out.index("## Findings"):out.index("## Coverage")]
    assert "None recorded." in findings_section
    assert "scanned" not in findings_section.lower()


# --- F5: the Surfaces column counts distinct surfaces, not check_run rows --

def test_the_surfaces_column_counts_distinct_surfaces_not_check_run_rows():
    """One surface, scanned in two separate runs by the same check: the
    table must say 1, never 2. `COUNT(*)` (the review's measured defect)
    would say 2 here, and scaled with every retest -- always upward, the
    direction a coverage figure must not lie in."""
    conn = _conn()
    _run(conn, "r-1", started_us=1)
    _run(conn, "r-2", started_us=2)
    _surface(conn, "s-1")
    _check_run(conn, "cr-1", run_id="r-1", surface_id="s-1",
              check_id="hx.test.dup", verdict="clean")
    _check_run(conn, "cr-2", run_id="r-2", surface_id="s-1",
              check_id="hx.test.dup", verdict="clean")
    out = report.render(conn=conn, engagement_id="e-1", config=_config())
    conn.close()
    assert "| `hx.test.dup` | clean | 1 |" in out
    assert "| `hx.test.dup` | clean | 2 |" not in out


# --- F6: rendered + omitted must equal the true total, and both are pinned -

def test_evidence_accounts_for_rows_that_do_not_resolve(report_env_with_unresolvable_evidence):
    """8 rows in the store: 1 resolves, 4 fall inside the cap's first 5 slots
    but do not resolve (consumed a slot, rendered nothing), 3 are beyond the
    cap. All three numbers must be visible and correct -- silently dropping
    the 4 unresolved ones would leave "1 rendered + 3 omitted = 4", four
    short of 8."""
    out = report.render(**report_env_with_unresolvable_evidence)
    section = out[out.index("**Evidence.**"):]
    bullets = [l for l in section.splitlines() if l.startswith("- `GET")]
    assert len(bullets) == 1
    assert "3 further evidence row(s) omitted" in out
    assert "first 5 of 8" in out
    assert "4 of the 5 shown could not be resolved" in out


def test_a_long_evidence_chain_is_capped_and_says_so(report_env_with_long_evidence_chain):
    """8 evidence rows in the store; the render must show fewer and say that
    it did, rather than either printing all 8 or silently dropping the rest
    with no word said. F6/F7 of the review: the total in the caveat is
    pinned to the literal store count (8), not `len(shown)` (5) -- mutating
    `{total}` to `{len(shown)}` used to leave 14 passing."""
    out = report.render(**report_env_with_long_evidence_chain)
    bullets = [line for line in out.splitlines() if line.startswith("- `GET")]
    assert 0 < len(bullets) < 8
    assert "omitted" in out.lower()
    assert "first 5 of 8" in out


def test_the_evidence_cap_is_not_labelled_with_the_word_observation(
        report_env_with_long_evidence_chain):
    """F11 (fix round B): the cap line used to say "3 further observation(s)
    omitted". `finding_observation` is this schema's word for PRESENCE PER
    RUN -- what `_latest_observed` reads, and what the "appears fixed" marker
    a few lines above is built from -- so a reader takes "the first 5 of 8"
    as eight RUNS. They are unrelated numbers: `evidence` rows are exchanges
    and one run contributes several. The caveat must not use the word at
    all, and it must still say the two numbers it exists to say."""
    out = report.render(**report_env_with_long_evidence_chain)
    capped = [line for line in out.splitlines() if "omitted" in line]
    assert len(capped) == 1
    assert "observation" not in capped[0].lower()
    assert "3 further evidence row(s) omitted" in capped[0]
    assert "first 5 of 8" in capped[0]


def test_a_short_evidence_chain_is_not_reported_as_capped(report_env_with_findings):
    """The separating case: a chain that never approached the bound must not
    claim rows were omitted. A caveat that is always present is not a
    caveat -- the same rule the no-drops test above applies to the floor
    line, applied here to the evidence bound."""
    assert "omitted" not in report.render(**report_env_with_findings).lower()


# --- F7: the body-probe limit does not depend on a profile that does not --
# --- decide it ---------------------------------------------------------

def test_the_body_probe_limit_holds_regardless_of_safety_profile(report_env):
    """`Policy.java`'s `DEFAULT_METHODS` comment (:162-171) says the
    GET/HEAD/OPTIONS allowlist applies whenever `method.allow` is absent
    from the config body "whatever profile the configure frame named" --
    and Python's `Config` has no `method.allow` field at all, so that is
    every engagement this CLI can build. The old bullet only showed for
    `safety_profile == "production"`; a staging report silently dropped a
    limit that was equally true of it."""
    env = dict(report_env)
    env["config"] = _config(safety_profile="staging")
    out = report.render(**env)
    assert "request-body parameters" in out.lower()


def test_the_body_probe_limit_also_holds_for_the_production_default(report_env):
    out = report.render(**report_env)
    assert "request-body parameters" in out.lower()


# --- F8: the blobs=None guard is observable even when surfaces exist -------

def test_the_blobs_none_guard_holds_even_when_a_surface_has_a_capture(report_env_with_surface_but_no_blobstore):
    """The separating case for F8: a real surface with a `req_blob` digest
    exists, and `blobs=None`. Before the fix, a bare `except Exception`
    around `blobs.get` swallowed the resulting `AttributeError` and made
    this indistinguishable from "no surfaces to iterate" -- deleting the
    `if blobs is not None:` guard left 14 passing regardless."""
    out = report.render(**report_env_with_surface_but_no_blobstore)
    assert "Insertion points" not in out


# --- F9: a finding not observed in the latest run says so -------------------

def test_a_finding_not_observed_in_the_latest_run_says_so(report_env_with_fixed_finding):
    """`finding_observation` carries the exact datum Tasks 5 and 6 spent
    three fix rounds making correct -- `observed=0` is "the exact datum a
    retest renders as fixed" (`scan.py`'s own words) -- and this report used
    to never read it at all. A finding gone as of the latest run rendered
    byte-identical to a live one."""
    out = report.render(**report_env_with_fixed_finding)
    assert "appears fixed" in out.lower()


def test_a_finding_reconfirmed_in_the_latest_run_carries_no_fixed_marker(report_env_with_reconfirmed_finding):
    """The separating case: a finding actually still live in the latest run
    must not be marked fixed."""
    out = report.render(**report_env_with_reconfirmed_finding)
    assert "appears fixed" not in out.lower()


def test_a_finding_never_retested_carries_no_fixed_marker(report_env_with_findings):
    """A second separating case: a finding found once and never retested has
    no second data point. `None`, not `False` -- it must not render as
    fixed either."""
    out = report.render(**report_env_with_findings)
    assert "appears fixed" not in out.lower()


def test_the_fixed_marker_names_the_mechanism_not_the_latest_run(report_env_fixed_then_a_skipped_run):
    """R2 (fix round 2): run 3 is chronologically the most recent run of the
    engagement, and it never tested this finding's surface (no
    `finding_observation` row for it) -- the datum the marker is built from
    still correctly comes from run 2 (fixed), but the OLD wording ("not
    observed in the most recent run") was false of this exact case: run 3
    IS the most recent run, and it never observed anything about this
    finding at all. The marker must still fire (the finding really is fixed
    as of the last run that tested it) but must not use the false phrase."""
    out = report.render(**report_env_fixed_then_a_skipped_run)
    assert "appears fixed" in out.lower()
    assert "not observed in the most recent run" not in out.lower()


# --- F11: an enabled-but-unshipped check class is named in Coverage --------

def test_an_enabled_but_unshipped_check_class_is_named_in_coverage(report_env):
    """`hx scan` already tells the operator when an enabled class ships no
    checks (`cli.py`'s own note); the report is the durable artifact and
    must say the same thing. `active_timing` is on by default
    (`config.DEFAULT_CHECKS`) and this build ships nothing in it."""
    out = report.render(**report_env)
    assert "active_timing" in out
    assert "ships no checks" in out.lower()


def test_no_unshipped_note_when_every_check_class_is_disabled(report_env):
    """The separating case: with every class turned off in config, none of
    them is "enabled but unshipped" -- there is nothing to note."""
    env = dict(report_env)
    env["config"] = _config(checks={k: False for k in config_mod.DEFAULT_CHECKS})
    out = report.render(**env)
    assert "ships no checks" not in out.lower()


# --- F13: smaller defects, each with its own separating input --------------

def test_a_reason_containing_a_pipe_or_newline_does_not_corrupt_the_coverage_table():
    """`check_run.reason` is exception text and can contain either -- a raw
    `|` splits a table cell, a raw newline ends the row. Both must be
    escaped, not dropped: the row still has to say what happened."""
    conn = _conn()
    _run(conn, "r-1")
    _surface(conn, "s-1")
    _check_run(conn, "cr-1", run_id="r-1", surface_id="s-1",
              check_id="hx.test.pipe", verdict="error",
              reason="CorruptBlob: a|b\nsecond line")
    out = report.render(conn=conn, engagement_id="e-1", config=_config())
    conn.close()
    rows = [l for l in out.splitlines() if l.startswith("| `hx.test.pipe`")]
    assert len(rows) == 1
    assert "a\\|b second line" in rows[0]


def test_findings_within_a_severity_are_ordered_deterministically():
    """No `ORDER BY` on the finding query meant within-severity order was
    whatever SQLite happened to return -- fine until a retest diff needs it
    stable.

    `_finding()`'s own dedupe key uses `type_=title` for convenience, which
    made an earlier version of this test measure nothing: `finding` carries
    a `UNIQUE(engagement_id, dedupe_key)` index, dedupe_key's FIRST field is
    `type_`, and a plan query with no `ORDER BY` can be satisfied by a scan
    of that index -- sorted by dedupe_key, which sorted by title too,
    because `type_` WAS the title. Dropping the report's own `ORDER BY`
    still came back alphabetical by coincidence, measured directly while
    sweeping this fix. Real findings never key on title this way (`scan.py`
    uses `check.id`), so this test builds the dedupe key directly, with the
    key's own order running OPPOSITE the titles': `insertion_name`, the
    LAST field, is `"zzz"` for the finding titled "Alpha issue" and `"aaa"`
    for "Zebra issue" -- an index scan by dedupe_key would render Zebra
    before Alpha, and only an actual `ORDER BY title` renders Alpha first.
    """
    conn = _conn()
    _run(conn, "r-1")
    _exchange(conn, "x-1", "r-1", "https://app.acme.test/a")
    _exchange(conn, "x-2", "r-1", "https://app.acme.test/b")
    for title, exchange_id, tiebreak in (
        ("Zebra issue", "x-1", "aaa"), ("Alpha issue", "x-2", "zzz"),
    ):
        c = base.Candidate(title=title, issue_type_id="ordering-fixture",
                           severity="Low", confidence="Firm",
                           insertion=None, exchange_ids=(exchange_id,))
        key = records.dedupe_key(
            type_="hx.test.order", issue_type_id="ordering-fixture",
            scheme="https", host="app.acme.test",
            port=443, method="GET", path_template="/",
            insertion_kind="query", insertion_name=tiebreak,
            scope_level="surface")
        fid = records.upsert_finding(conn, engagement_id="e-1", candidate=c,
                                     dedupe_key=key, run_id="r-1")
        records.record_evidence(conn, finding_id=fid,
                                exchange_ids=(exchange_id,), at_us=1)
    out = report.render(conn=conn, engagement_id="e-1", config=_config())
    conn.close()
    assert out.index("Alpha issue") < out.index("Zebra issue")


def test_severity_headings_nest_under_findings_not_beside_it(report_env_with_findings):
    """`## High` used to sit at the same heading level as `## Findings` --
    a sibling section, not a child of it. `### High` nests it correctly, and
    the check has to be an exact line match: `### High` also CONTAINS the
    substring `"## High"`, so a naive `in` check cannot tell the fixed
    heading from the bug."""
    out = report.render(**report_env_with_findings)
    lines = [l.rstrip() for l in out.splitlines()]
    assert "### High" in lines
    assert "## High" not in lines


def test_a_null_exchange_status_does_not_render_as_the_bare_word_none(report_env_with_findings):
    """Every exchange this file's `_exchange()` helper builds now sets a
    real `status=200`, EXCEPT this is the one place that deliberately does
    not: `exchange.status` is nullable (a timeout or a refusal never gets
    one), and `str(None)` rendered as the literal word "None" in a client
    document."""
    conn = _conn()
    _run(conn, "r-1")
    conn.execute(
        "INSERT INTO exchange(id, run_id, via, outcome, sent_us, method,"
        " url, status) VALUES('x-1','r-1','proxy','timeout',1,'GET',"
        "'https://app.acme.test/slow', NULL)")
    _finding(conn, run_id="r-1", title="Timeout during scan", severity="Low",
            exchange_ids=["x-1"])
    out = report.render(conn=conn, engagement_id="e-1", config=_config())
    conn.close()
    assert "→ None" not in out
    assert "no status recorded" in out
