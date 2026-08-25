"""Every Python constant that mirrors a schema CHECK, pinned against it.

This file exists because of one measured incident and one near-miss.

THE INCIDENT. Plan 4 amended §5 to say `run.kind` is
`browse | crawl | manual | scan`. The schema's CHECK still named
`('manual','scheduled','retest')` -- values from before the proxy existed --
and nothing noticed until Task 3 tried to open a run and got
`IntegrityError` fourteen times. The spec text and the constraint had drifted,
and a whole task attempt was spent discovering it.

THE NEAR-MISS. The commit that fixed it verified the four values BY HAND, at a
Python prompt. Task 3's mutation sweep then found that `RUN_KINDS`'s contents
were pinned by nothing at all: dropping `"scan"`, or re-admitting `"scheduled"`,
reddened no test. So the fix for a drift left the next drift equally
undetectable, which is the shape this project keeps finding -- a guard that is
real, correct, and invisible.

So the rule is not "check run.kind". It is: A VOCABULARY THAT EXISTS IN TWO
PLACES MUST BE COMPARED IN ONE. The schema is the authority here because it is
what actually refuses a bad write; the Python constants exist to give a caller
a better message than SQLite's, and a better message about the wrong set is
worse than no message.

The sets below are DERIVED from `schema.sql`, never restated. A test that
restated them would be a third copy and would drift in its turn.
"""
from __future__ import annotations

import re

import pytest

from hx import capture as capture_mod
from hx import config as config_mod
from hx import run as run_mod
from hx.store import db as db_mod
from hx.store import records as records_mod

# `CHECK (col IN ('a','b', 'c'))`, including the multi-line form the schema
# uses for the longer vocabularies. Non-greedy to the first `)` that closes the
# IN list, which is safe because no value in this schema contains a paren.
_CHECK = re.compile(
    r"CHECK\s*\(\s*(?P<col>\w+)\s+IN\s*\((?P<values>[^)]*)\)", re.S)
_VALUE = re.compile(r"'([^']*)'")


_TABLE = re.compile(r"CREATE TABLE(?:\s+IF NOT EXISTS)?\s+(\w+)", re.I)


def _checks() -> dict[str, frozenset[str]]:
    """Every `col IN (...)` CHECK in the schema, keyed `table.column`.

    Keyed by table AND column, because the first version of this helper keyed
    by column alone on the assumption that no two tables gave the same column
    name different vocabularies. That assumption was wrong on its first run, in
    two places: `kind` is one thing on `run`, another on `surface`, another on
    `denial`; `status` differs across `engagement`, `run` and `finding`. The
    anti-vacuity guard caught it rather than a silent last-write-wins, which is
    the only reason this docstring is not still asserting something false.
    """
    sql = db_mod._schema_sql()
    boundaries = [(m.start(), m.group(1)) for m in _TABLE.finditer(sql)]

    def table_at(pos: int) -> str:
        name = "<before any table>"
        for start, table in boundaries:
            if start > pos:
                break
            name = table
        return name

    out: dict[str, frozenset[str]] = {}
    for m in _CHECK.finditer(sql):
        key = f"{table_at(m.start())}.{m.group('col')}"
        values = frozenset(_VALUE.findall(m.group("values")))
        if key in out and out[key] != values:
            pytest.fail(f"two CHECKs on {key} disagree: "
                        f"{sorted(out[key])} vs {sorted(values)}")
        out[key] = values
    return out


def test_the_parser_found_the_constraints_rather_than_nothing():
    """Anti-vacuity, and it is not decorative.

    Every assertion below is `constant == schema[col]`. If the parser silently
    returned an empty mapping, each of those would raise KeyError -- but a
    subtler failure, where the regex matched the column and captured no values,
    would compare against an empty set and could be "fixed" by emptying the
    constant. So the shape of the parse is pinned here, once.
    """
    checks = _checks()
    assert len(checks) >= 15, f"only parsed {len(checks)} CHECK constraints"
    assert all(v for v in checks.values()), \
        f"parsed an EMPTY value set for: {[k for k, v in checks.items() if not v]}"
    # A spot value the schema definitely contains, so a regex that matched
    # structure but not content cannot pass.
    assert "browse" in checks["run.kind"]


def test_run_kinds_matches_the_schema():
    """The incident this file exists for.

    §5's vocabulary, the CHECK, and `RUN_KINDS` are one fact. Task 3's sweep
    found that dropping `"scan"` from the constant reddened nothing, and that
    re-admitting the retired `"scheduled"` reddened nothing either -- so the
    constant could have drifted back to the very values that broke the task.
    """
    assert set(run_mod.RUN_KINDS) == _checks()["run.kind"]


def test_valid_profiles_matches_the_schema():
    assert set(config_mod.VALID_PROFILES) == _checks()["run.safety_profile"]


def test_exchange_outcomes_matches_the_schema():
    """`records.EXCHANGE_OUTCOMES` against `exchange.outcome`.

    Amended twice during Plan 3 -- `status_unreadable` was added on a
    measurement against real Burp -- so this pairing has already moved once
    under load.
    """
    checks = _checks()
    assert set(records_mod.EXCHANGE_OUTCOMES) == checks["exchange.outcome"]
    # And the MAP whose values feed the same column. It is narrower than the
    # set above by design -- most outcomes name no error class -- so this half
    # is a subset check, and it is the half that catches an error class mapped
    # onto an outcome the CHECK will refuse.
    assert set(records_mod.EXCHANGE_OUTCOME.values()) <= checks["exchange.outcome"]


def test_denial_kinds_matches_the_schema():
    """`records.DENIAL_KINDS` against `denial.kind`.

    This one is derived twice over: DENIAL_KINDS is the value set of
    DENIAL_KIND, which maps error CLASSES to schema KINDS. A class added
    without a kind, or a kind the schema will refuse, both land here.
    """
    assert set(records_mod.DENIAL_KINDS) == _checks()["denial.kind"]


def test_via_values_matches_the_schema():
    """`records.VIA_VALUES` against `exchange.via` AND `denial.via`.

    Two columns, because Plan 4 added the second: `exchange` has carried `via`
    since Plan 1, `denial` never did, and the omission was invisible while the
    send path was the only writer of either. Comparing against one of them
    would leave the other free to drift, which is this file's whole subject --
    and `_checks()` keys by table AND column precisely because a shared column
    name is not a shared vocabulary.
    """
    checks = _checks()
    assert set(records_mod.VIA_VALUES) == checks["exchange.via"]
    assert set(records_mod.VIA_VALUES) == checks["denial.via"]


def test_discovered_by_is_total_over_via_and_says_only_what_the_schema_takes():
    """`hx.capture.DISCOVERED_BY` against BOTH vocabularies it sits between.

    It is a map, not a set, and both halves can drift on their own. Its KEYS
    must cover `via` completely or an egress point this store already accepts
    raises KeyError on the first surface it discovers -- `via` is checked
    against VIA_VALUES a few lines earlier, so a fourth value would pass that
    check and die here. Its VALUES must be ones `surface.discovered_by`'s
    CHECK accepts, or the INSERT fails at the far end instead.

    The two vocabularies are deliberately NOT the same: S5 spells the egress
    point `send` and the discovery `agent`, so this cannot be an identity map
    and the pairing has to be stated.
    """
    checks = _checks()
    assert set(capture_mod.DISCOVERED_BY) == set(records_mod.VIA_VALUES)
    assert set(capture_mod.DISCOVERED_BY.values()) <= checks["surface.discovered_by"]


def test_every_python_vocabulary_in_this_repo_is_covered_here():
    """The list of pairings is itself a thing that drifts.

    A new module-level frozenset of string literals that mirrors a CHECK is
    exactly what this file exists to pin, and adding one without adding a test
    here recreates the hole. So the pairings are enumerated, and any
    module-level vocabulary constant not named must be either added above or
    named as deliberately unpaired.

    DICTS ARE SCANNED TOO, and they were not until Plan 4's Task 4 added
    `hx.capture.DISCOVERED_BY` -- a map whose keys are one vocabulary and
    whose values are another. Turning the scan on found three more that had
    been invisible to it all along, two of them in `records`. A map between
    two CHECK-constrained columns is more exposed than a set, not less: it can
    drift at either end.
    """
    paired = {
        "hx.capture.DISCOVERED_BY",
        "hx.run.RUN_KINDS",
        # The two error-class MAPS. Their KEYS are the wire vocabulary and are
        # pinned in test_records.py against the emit sites; their VALUES are
        # column vocabularies and are pinned above -- DENIAL_KIND through
        # DENIAL_KINDS, which is its own value set, and EXCHANGE_OUTCOME by
        # the subset assertion in test_exchange_outcomes_matches_the_schema.
        "hx.store.records.DENIAL_KIND",
        "hx.store.records.EXCHANGE_OUTCOME",
        "hx.config.VALID_PROFILES",
        "hx.store.records.EXCHANGE_OUTCOMES",
        "hx.store.records.DENIAL_KINDS",
        "hx.store.records.VIA_VALUES",
    }
    unpaired_with_reason = {
        # Error CLASSES are a wire vocabulary from §6, not a column. The
        # schema never stores one; `row_for` maps them onto columns that are
        # pinned above.
        "hx.store.records.ERROR_CLASSES",
        "hx.store.records.UNRECORDABLE",
        "hx.store.records.NO_STATUS_OUTCOMES",
        "hx.store.records.AMBIGUOUS_ISSUANCE",
        # Error classes refused BEFORE the JVM issues anything. Same wire
        # vocabulary, no column: a pre-issuance refusal produces a `denial`
        # row whose KIND is pinned above, never an `exchange`.
        "hx.store.records.PRE_ISSUANCE",
        # The WIRE's frame types, from S6 and docs/bridge-protocol.md. No
        # column holds one: a frame's `t` decides which table it becomes a row
        # in, and the vocabularies of those tables are pinned above. It is
        # here rather than absent because the scan below would otherwise not
        # notice a fourth frame type appearing with nowhere to be decided
        # about.
        "hx.capture.FRAME_TYPES",
        # Which CHECK FAMILIES are enabled, from the config file. Plan 6's
        # subject; no column holds the set, and `config.load` refuses a key
        # outside it directly.
        "hx.config.DEFAULT_CHECKS",
    }
    found = set()
    for mod, name in ((run_mod, "hx.run"), (config_mod, "hx.config"),
                      (capture_mod, "hx.capture"),
                      (records_mod, "hx.store.records")):
        for attr in dir(mod):
            if attr.startswith("_") or not attr.isupper():
                continue
            value = getattr(mod, attr)
            if isinstance(value, (frozenset, set, tuple, dict)) and value and \
                    all(isinstance(v, str) for v in value):
                found.add(f"{name}.{attr}")
    # The widening this test just gained, pinned by its one witness. Both
    # halves of it were unheld: reverting `dict` from the isinstance tuple
    # above, and dropping `capture_mod` from the modules scanned, each left
    # the whole suite green -- `537 passed`, measured at the commit before
    # this assertion existed -- either edit silently restoring the blind spot
    # that hid a map between two CHECK-constrained columns. A scan whose
    # reach is not asserted is a scan that can be narrowed by accident.
    assert "hx.capture.DISCOVERED_BY" in found, (
        "the scan no longer reaches hx.capture, or no longer looks at dicts; "
        "either way the map it was widened to catch is invisible to it again"
    )
    unaccounted = found - paired - unpaired_with_reason
    assert not unaccounted, (
        f"vocabulary constants with no pairing and no reason: {sorted(unaccounted)}. "
        "Either pin it against its schema CHECK above, or add it to "
        "unpaired_with_reason with the reason it has no column.")
