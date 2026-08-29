"""What a check is allowed to say, and what it is not.

`check_run.verdict` carries six values; a check may return three. The other
three -- `pending`, `skipped`, `error` -- are the RUNNER's words, because a
check that can call itself skipped can hide the fact that it never ran, and
that is the failure S12 says is worse than no report at all.
"""
import pytest

from hx.checks import base


@pytest.fixture
def a_candidate():
    return base.Candidate(title="t", issue_type_id="t-issue",
                           severity="Low", confidence="Firm",
                           insertion=None, exchange_ids=("x-1",))


def test_a_clean_verdict_carries_no_candidates_and_no_reason():
    v = base.Verdict.clean()
    assert v.state == "clean"
    assert v.candidates == ()
    assert v.reason is None


def test_inconclusive_requires_a_reason():
    """S10: a check that cannot run returns inconclusive(reason), never clean.

    A reason-less inconclusive is the same failure one step removed: the
    report would say "could not test" without saying why, and the operator
    cannot act on it.
    """
    with pytest.raises(ValueError, match="reason"):
        base.Verdict.inconclusive("")


def test_a_finding_verdict_needs_at_least_one_candidate():
    """`finding` with nothing in it is a row claiming a finding that has no
    evidence, no title and no dedupe key. It is refused here rather than
    discovered when the upsert fails."""
    with pytest.raises(ValueError, match="candidate"):
        base.Verdict.finding()


def test_a_check_cannot_express_skipped_or_error_or_pending():
    """The separating test for this whole module. If any of these three ever
    becomes constructible, the runner's exclusive right to say them is gone
    and nothing else in the system would notice."""
    for word in ("skipped", "error", "pending"):
        assert not hasattr(base.Verdict, word)


def test_the_raw_constructor_also_refuses_skipped_error_and_pending():
    """The classmethod test above pins that `Verdict.skipped` etc. don't
    exist; it says nothing about `Verdict("skipped")` called directly. Fix
    round 1: that bare constructor call built successfully with no
    `__post_init__` on `Verdict`, unlike `Candidate` and `Insertion` -- the
    same bypass that let `Verdict("inconclusive")` skip its required reason.
    This is the test that separates "the constructor validates state" from
    "it doesn't": delete `Verdict.__post_init__` and this reddens."""
    for word in ("skipped", "error", "pending"):
        with pytest.raises(ValueError, match="state"):
            base.Verdict(word)


def test_the_raw_constructor_also_refuses_an_empty_finding():
    with pytest.raises(ValueError, match="candidate"):
        base.Verdict("finding")


def test_the_raw_constructor_also_refuses_a_reasonless_inconclusive():
    with pytest.raises(ValueError, match="reason"):
        base.Verdict("inconclusive")


def test_candidate_defaults_to_surface_scope():
    c = base.Candidate(title="t", issue_type_id="t-issue",
                       severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    assert c.scope_level == "surface"


def test_candidate_refuses_a_severity_the_schema_will_not_take():
    """The schema's CHECK is Critical|High|Medium|Low|Info. Refusing here
    names the value; SQLite would answer `CHECK constraint failed: finding`."""
    with pytest.raises(ValueError, match="severity"):
        base.Candidate(title="t", issue_type_id="t-issue",
                       severity="Catastrophic", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))


def test_candidate_requires_an_issue_type_id():
    """F1 of the whole-branch review, HIGH. `issue_type_id` is the ONLY part
    of the dedupe key that separates two candidates from ONE check against
    ONE surface, so a check that forgets it collapses its own findings onto
    one row. Refused at construction, the way an empty title is, rather than
    discovered as a missing finding in a delivered report."""
    with pytest.raises(ValueError, match="issue_type_id"):
        base.Candidate(title="t", issue_type_id="", severity="Low",
                       confidence="Firm", insertion=None,
                       exchange_ids=("x-1",))


def test_candidate_requires_evidence():
    """A finding with no exchange behind it cannot have an evidence chain, and
    S12's report renders one per finding."""
    with pytest.raises(ValueError, match="exchange"):
        base.Candidate(title="t", issue_type_id="t-issue",
                       severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=())


def test_an_insertion_names_a_known_kind_and_a_name():
    """`Insertion.__post_init__` had no test anywhere in the repo before this
    fix round. A legal one just needs a kind the schema-adjacent
    `INSERTION_KINDS` set knows and a non-empty name."""
    i = base.Insertion(kind="query", name="id")
    assert i.kind == "query"
    assert i.name == "id"


def test_an_insertion_refuses_an_unknown_kind():
    with pytest.raises(ValueError, match="kind"):
        base.Insertion(kind="fragment", name="id")


def test_an_insertion_refuses_an_empty_name():
    with pytest.raises(ValueError, match="name"):
        base.Insertion(kind="query", name="")


def test_a_clean_verdict_can_name_what_it_considered():
    v = base.Verdict.clean(considered=("missing-hsts", "missing-xcto"))
    assert v.state == "clean"
    assert v.considered == ("missing-hsts", "missing-xcto")


def test_a_finding_verdict_can_name_what_it_considered(a_candidate):
    v = base.Verdict.finding(a_candidate, considered=("missing-hsts",))
    assert v.considered == ("missing-hsts",)


def test_considered_defaults_to_empty_so_an_unaware_check_retires_nothing():
    # The failure mode of a check that never populates `considered` must be a
    # finding staying live, never a finding falsely closed.
    assert base.Verdict.clean().considered == ()


def test_inconclusive_cannot_name_considered_issue_types():
    # S10: a check that cannot run says so. It concluded nothing, so it may
    # not retire anything -- the classmethod does not offer the argument.
    with pytest.raises(TypeError):
        base.Verdict.inconclusive("bridge_lost", considered=("missing-hsts",))


def test_considered_must_be_a_tuple_of_non_empty_strings():
    with pytest.raises(ValueError):
        base.Verdict("clean", (), None, ("",))
    with pytest.raises(ValueError):
        base.Verdict("clean", (), None, ("ok", 3))
