"""The registry is a list somebody maintains, and this is what it refuses.

Discovery was rejected for this corpus. The argument is in extension/test.sh
and it transfers exactly: a check nobody lists is a file that imports, never
runs, and renders in a report as `tested, clean`.
"""
import pytest

from hx.checks import base, registry


class _Passive:
    id, version, klass = "t.passive", "1", "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges):
        return base.Verdict.clean()


class _PassiveThatProbes(_Passive):
    id = "t.passive-that-probes"

    def probes(self, ctx, surface, insertion):
        return ()


class _NoHooks:
    id, version, klass = "t.no-hooks", "1", "passive"
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
