"""The registry is a list somebody maintains, and this is what it refuses.

Discovery was rejected for this corpus. The argument is in extension/test.sh
and it transfers exactly: a check nobody lists is a file that imports, never
runs, and renders in a report as `tested, clean`.
"""
import pytest

from hx.checks import base, registry


class _Passive:
    id, version, klass = "t.passive", "1", "passive"
    looks_for = "a category this test invented"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges):
        return base.Verdict.clean()


class _PassiveThatProbes(_Passive):
    id = "t.passive-that-probes"

    def probes(self, ctx, surface, insertions, send):
        return ()


class _NoHooks:
    id, version, klass = "t.no-hooks", "1", "passive"
    looks_for = "a category this test invented"
    insertion_kinds = frozenset()


def test_a_passive_check_implementing_probes_is_refused():
    """The separating case. `probes` is the active hook; a passive check
    carrying one either lies about its class or has a hook nothing will call,
    and both are worth failing at import rather than at scan time."""
    with pytest.raises(registry.RegistryError, match="probes"):
        registry.validate((_PassiveThatProbes(),))


def test_a_check_with_no_hook_at_all_is_refused():
    """It would produce `check_run` rows forever and never a verdict."""
    with pytest.raises(registry.RegistryError, match="no hook"):
        registry.validate((_NoHooks(),))


def test_duplicate_ids_are_refused():
    """`check_run.check_id` is how coverage is attributed. Two checks sharing
    an id make the coverage section unreadable and the retest wrong."""
    with pytest.raises(registry.RegistryError, match="duplicate"):
        registry.validate((_Passive(), _Passive()))


def test_an_unknown_class_is_refused():
    class _Weird(_Passive):
        id, klass = "t.weird", "active_telepathy"
        looks_for = "a category this test invented"
    with pytest.raises(registry.RegistryError, match="active_telepathy"):
        registry.validate((_Weird(),))


def test_the_shipped_registry_validates():
    """Anti-vacuity, and the reason this file is not just unit tests of a
    validator: the real CHECKS tuple must pass its own rules."""
    registry.validate(registry.CHECKS)
    assert len(registry.CHECKS) >= 1


def test_enabled_reads_the_engagement_config():
    """config.DEFAULT_CHECKS already carries S10's five class names. A class
    switched off there must not run, and `enabled` is the one place that is
    decided."""
    from hx import config as config_mod
    cfg = config_mod.Config(name="t", client="t", scope_include=["https://a/*"])
    cfg.checks["passive"] = False
    assert all(c.klass != "passive" for c in registry.enabled(cfg))


def test_every_shipped_check_id_is_namespaced():
    """`hx.` prefixes ours. A per-engagement corpus is a later, additive
    change, and the prefix is what will keep the two apart without a rename."""
    for check in registry.CHECKS:
        assert check.id.startswith("hx."), check.id


# --- Whole-branch review F7 (LOW): `_HOOKS` blessed `on_corpus` for every
# class, and `hx.scan.run` calls no such hook.


class _OnlyCorpus:
    id, version, klass = "t.only-corpus", "1", "passive"
    looks_for = "a category this test invented"
    insertion_kinds = frozenset()

    def on_corpus(self, ctx, surfaces):
        return ()


class _SurfaceAndCorpus(_Passive):
    id = "t.surface-and-corpus"

    def on_corpus(self, ctx, surfaces):
        return ()


class _ActiveThatOnlyProbes:
    id, version, klass = "t.only-probes", "1", "active_safe"
    looks_for = "a category this test invented"
    insertion_kinds = frozenset()

    def probes(self, ctx, surface, insertions, send):
        return ()


def test_a_check_whose_only_hook_the_runner_never_calls_is_refused():
    """F7. `on_corpus` is LEGAL for a passive class -- `_HOOKS` says so, and
    that is a statement about the class, not about the runner. `scan.run`
    calls `on_surface` and nothing else, so this check passed validate() and
    then wrote an `error` row per surface: `scan.run` calls
    `check.on_surface` unconditionally and the missing attribute raises
    inside the per-check try. That is verbatim the outcome the `no hook`
    guard exists to prevent, reached by a different route."""
    with pytest.raises(registry.RegistryError, match="does not yet call"):
        registry.validate((_OnlyCorpus(),))


def test_an_active_check_that_only_probes_is_accepted_now_the_pass_exists():
    """THE REFUSAL LIFTED BY THE RUNNER CHANGING, NOT BY THE RULE CHANGING.

    Until Plan 6's Task 7 this check was refused, and the message said so in
    the right words: the hook is legal for its class and the pass that would
    drive it was not written. `hx.scan.run` now has that pass, `probes` is in
    `_RUNNER_CALLS`, and the same rule applied to the same check therefore
    accepts it. The test below pins that `on_corpus` -- still uncalled -- is
    still refused, which is what makes this an outcome of the rule rather
    than an exemption carved out of it."""
    registry.validate((_ActiveThatOnlyProbes(),))


def test_the_probe_hook_is_listed_as_one_the_runner_calls():
    """The registry's half of the seam, asserted directly.

    The test above passes if the refusal stops firing, and there is more than
    one way to stop a refusal firing: deleting the `_RUNNER_CALLS` guard from
    `validate` would do it for every check at once and leave nothing here
    red. Naming the tuple's contents -- `probes` in, `on_corpus` still out --
    is what separates "the pass was added" from "the guard was loosened"."""
    assert "probes" in registry._RUNNER_CALLS
    assert "on_surface" in registry._RUNNER_CALLS
    assert "on_corpus" not in registry._RUNNER_CALLS


def test_a_check_carrying_on_corpus_ALONGSIDE_on_surface_is_accepted():
    """The separating case. The rule refuses a check the runner cannot drive
    at all, not every mention of a hook a later plan will call -- rejecting
    this one would forbid writing the corpus pass's checks incrementally."""
    registry.validate((_SurfaceAndCorpus(),))


def test_the_refusal_names_the_runner_rather_than_blaming_the_check():
    """The next person to write a corpus check should learn WHY from the
    error, not guess. It names the hooks the runner does call and where to
    add one."""
    with pytest.raises(registry.RegistryError) as exc:
        registry.validate((_OnlyCorpus(),))
    message = str(exc.value)
    assert "on_surface" in message          # what the runner does call
    assert "_RUNNER_CALLS" in message       # where to add a new one
