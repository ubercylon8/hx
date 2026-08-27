"""What a check is allowed to say, and what it is not.

`check_run.verdict` carries six values; a check may return three. The other
three -- `pending`, `skipped`, `error` -- are the RUNNER's words, because a
check that can call itself skipped can hide the fact that it never ran, and
that is the failure S12 says is worse than no report at all.
"""
import pytest

from hx.checks import base


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
    c = base.Candidate(title="t", severity="Low", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))
    assert c.scope_level == "surface"


def test_candidate_refuses_a_severity_the_schema_will_not_take():
    """The schema's CHECK is Critical|High|Medium|Low|Info. Refusing here
    names the value; SQLite would answer `CHECK constraint failed: finding`."""
    with pytest.raises(ValueError, match="severity"):
        base.Candidate(title="t", severity="Catastrophic", confidence="Firm",
                       insertion=None, exchange_ids=("x-1",))


def test_candidate_requires_evidence():
    """A finding with no exchange behind it cannot have an evidence chain, and
    S12's report renders one per finding."""
    with pytest.raises(ValueError, match="exchange"):
        base.Candidate(title="t", severity="Low", confidence="Firm",
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
