"""A crawl that submits no forms and clicks nothing must say so.

S12's rule, and the mechanism the Findings scope line established on
2026-09-02: the report states the boundary in the same place it states the
result. Without this, an engagement that crawled reports a crawl's coverage
and discloses none of its four gaps.
"""
from __future__ import annotations

from hx import config as config_mod
from hx import report as report_mod


def _cfg():
    return config_mod.Config(name="T", client="T", safety_profile="staging",
                             scope_include=["https://app.test/*"])


def _crawled(conn):
    conn.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r-c','e-1','crawl','staging',1,'completed')")


def test_an_engagement_that_crawled_discloses_what_the_crawl_did_not_do(
        engagement_conn):
    """MUTATION: delete any one of the four disclosures. Must go red.

    Parametrised over the four rather than asserted as one string, so that
    losing exactly one cannot hide behind the other three. The two phrases
    that read as ordinary English words elsewhere in the report --
    "interaction" (the no-blind-only-checks bullet) and "unauthenticated"
    (the every-probe-was-sent-unauthenticated bullet, which this minimal
    engagement also renders, having proved no session) -- are asserted by
    the LONGER phrase unique to the crawl bullet, so this test cannot pass
    on the strength of an unrelated bullet that happens to share one word.
    """
    _crawled(engagement_conn)
    out = report_mod.render(engagement_conn, engagement_id="e-1",
                            config=_cfg())
    for phrase in ("no forms", "clicks nothing", "interaction to reach",
                   "runs **unauthenticated**"):
        assert phrase in out.lower(), phrase


def test_an_engagement_that_did_not_crawl_keeps_its_own_sentence(
        engagement_conn):
    """THE SEPARATING CASE. The `else` branch predates this task and is
    correct; this pins that adding the disclosures did not displace it.

    MUTATION: render the crawl disclosures unconditionally. Must go red --
    a proxy-only engagement would be told what its crawler did not do.
    """
    out = report_mod.render(engagement_conn, engagement_id="e-1",
                            config=_cfg())
    assert "No automated crawl" in out
    assert "clicks nothing" not in out.lower()


def test_the_degraded_wording_does_not_overstate(engagement_conn):
    """A degraded page MAY not have rendered; we cannot know that it did
    not. S12's asymmetry runs the other way here -- see page.classify's own
    note about false degradation.

    MUTATION: change the copy to "did not render". Must go red.
    """
    _crawled(engagement_conn)
    out = report_mod.render(engagement_conn, engagement_id="e-1",
                            config=_cfg())
    assert "did not render" not in out.lower()
