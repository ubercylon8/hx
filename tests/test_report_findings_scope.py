"""The Findings section states what this build looked for.

MEASURED 2026-09-02, the first end-to-end run of this harness. Against OWASP
Juice Shop the Findings section rendered exactly `None recorded.` and the
Coverage table rendered `hx.passive.security-headers | clean | 14`, while the
target was serving no Content-Security-Policy at all, a `/ftp` listing
containing `coupons_2013.md.bak`, and `/rest/admin/application-configuration`
returning 23 KB to an unauthenticated request.

Every verdict was correct. `security_headers` tests three headers and all
three passed or did not apply; there is no directory-listing check and no
authorisation check in the corpus. The defect is what the SUM says: a client
reading `None recorded.` above fourteen `clean` rows concludes the
application was assessed and found sound.

Section 12's rule -- a report that cannot distinguish "tested, clean" from
"never reached" is worse than no report -- was already enforced for
SURFACES, by Coverage's untested list. It was not enforced for the CORPUS's
own scope, which is the boundary a reader cannot see and cannot guess. The
Limits section states it, nine bullets and seventy lines below where the eye
lands.

This file pins the sentence that closes that gap, on all three branches of
`_findings` -- and pins that it is DERIVED, because a hardcoded list is a
list that goes stale the first time somebody adds a check.
"""
from __future__ import annotations

import pytest

from hx import config as config_mod
from hx import report as report_mod
from hx.checks import registry


def _cfg():
    return config_mod.Config(name="T", client="T", safety_profile="staging",
                             scope_include=["https://app.test/*"])


def _finding(conn, fid="f-1", severity="Low"):
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES(?,'e-1',?,'Missing HSTS',?,'Firm','check','new','surface')",
        (fid, f"k-{fid}", severity))


def _scanned(conn):
    """The shape that makes `cov.scanned` true: one check_run behind a run."""
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, discovered_by, normaliser_version)"
        " VALUES('s-1','e-1','GET','https','app.test',443,'/a','proxy',2)")
    conn.execute(
        "INSERT INTO check_run(id, run_id, surface_id, check_id, check_version,"
        " verdict) VALUES('c-1','r-1','s-1','hx.passive.security-headers','1',"
        "'clean')")


def _render(conn):
    return report_mod.render(conn, engagement_id="e-1", config=_cfg())


# --- the sentence itself ---------------------------------------------------

def test_a_clean_scan_says_what_it_looked_for(engagement_conn):
    """THE JUICE SHOP CASE. A completed scan that found nothing must not
    render a bare `None recorded.`

    MUTATION: delete the scope line from `_findings`. This test must go red.
    """
    _scanned(engagement_conn)
    out = _render(engagement_conn)

    assert "None recorded" in out
    assert "looked for" in out
    assert "was not looked for" in out


def test_the_scope_line_also_appears_when_there_are_findings(engagement_conn):
    """A LIST of findings implies completeness exactly as an empty one does --
    a client reads "here are the issues", not "here are the issues in ten
    categories". The boundary belongs on both branches.

    MUTATION: put the scope line only on the empty branch. Must go red.
    """
    _scanned(engagement_conn)
    _finding(engagement_conn)
    out = _render(engagement_conn)

    assert "Missing HSTS" in out
    assert "was not looked for" in out


def test_an_unscanned_engagement_keeps_its_own_qualifier_and_gains_this_one():
    """F4's qualifier and this one answer different questions -- "no scan has
    run" against "this is what a scan would have looked for" -- so both
    belong, and this pins that adding one did not displace the other."""
    import sqlite3

    from hx.store import db as db_mod
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.execute("PRAGMA foreign_keys=ON")
    db_mod.init_schema(conn)
    conn.execute("INSERT INTO engagement(id, name, client, created_us, status)"
                 " VALUES('e-1','T','T',1,'active')")

    out = report_mod.render(conn, engagement_id="e-1", config=_cfg())

    assert "has not been scanned" in out
    assert "looked for" in out


def test_an_unfinished_run_keeps_its_own_qualifier_and_gains_this_one(
        engagement_conn):
    """The same, for N2's qualifier."""
    _scanned(engagement_conn)
    engagement_conn.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r-9','e-1','scan','staging',1,'aborted')")

    out = _render(engagement_conn)

    assert "did not finish" in out
    assert "was not looked for" in out


# --- derived, not hardcoded ------------------------------------------------

def test_the_line_names_what_the_shipped_checks_look_for(engagement_conn):
    """Every enabled check contributes its own phrase. Read off the registry
    rather than spelled here, so this test cannot pass against a hardcoded
    sentence that happens to match today's corpus."""
    _scanned(engagement_conn)
    out = _render(engagement_conn)

    for check in registry.enabled(_cfg()):
        assert check.looks_for in out, (
            f"{check.id} ships but the Findings scope line does not say what "
            "it looks for")


def test_a_disabled_check_class_is_not_claimed_as_looked_for(engagement_conn):
    """THE SEPARATING CASE, and the one a hardcoded sentence gets wrong. An
    engagement that disables a check class must not have this line claim its
    categories were assessed -- that would be the exact false-coverage claim
    the line exists to prevent, stated by the fix itself.

    MUTATION: build the line from `registry.CHECKS` instead of
    `registry.enabled(config)`. This test must go red.
    """
    cfg = _cfg()
    cfg.checks["active_safe"] = False
    _scanned(engagement_conn)

    out = report_mod.render(engagement_conn, engagement_id="e-1", config=cfg)

    active = [c for c in registry.CHECKS if c.klass == "active_safe"]
    assert active, "fixture assumes this build ships active_safe checks"
    for check in active:
        assert check.looks_for not in out, (
            f"{check.id} is disabled for this engagement but the scope line "
            "still claims its category was looked for")


# --- the corpus cannot grow silently ---------------------------------------

def test_every_shipped_check_declares_what_it_looks_for():
    """A check joining the corpus without a phrase would vanish from the
    scope line and take its category's absence with it -- the line would
    under-claim and nothing would say so. `registry.validate` refuses it at
    import; this pins that the shipped corpus satisfies it."""
    for check in registry.CHECKS:
        assert isinstance(getattr(check, "looks_for", None), str)
        assert check.looks_for.strip(), check.id


def test_the_registry_refuses_a_check_with_no_looks_for():
    """MUTATION: drop the `looks_for` branch from `registry.validate`. This
    test must go red."""
    class Nameless:
        id = "hx.passive.nameless"
        version = "1"
        klass = "passive"
        insertion_kinds = frozenset()

        def on_surface(self, ctx, surface, exchanges):
            raise NotImplementedError

    with pytest.raises(registry.RegistryError, match="looks_for"):
        registry.validate((Nameless(),))


def test_a_phrase_is_a_phrase_and_not_a_sentence():
    """The phrases are joined into one sentence, so a trailing full stop or a
    sentence-case opening would render as `looked for: Missing headers. ·
    ...`. Pinned because it is the kind of thing a new check gets wrong once.

    AN ACRONYM MAY OPEN A PHRASE. The first draft of this rule demanded a
    lowercase first character outright and rejected "SQL injection detectable
    by...", which would have forced `sQL`. The rule is against SENTENCE case,
    not against capitals: an all-caps first word is an acronym and reads
    correctly mid-sentence.
    """
    for check in registry.CHECKS:
        assert not check.looks_for.endswith("."), check.id
        first = check.looks_for.split()[0]
        assert first.islower() or first.isupper(), (
            f"{check.id}: {first!r} is sentence case; use lowercase, or an "
            "acronym in full capitals")
