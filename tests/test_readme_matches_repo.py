"""The README states facts the code already knows. Derive them, don't retype them.

WHY THIS EXISTS. On 2026-09-03 the README said "There is no crawler yet",
"`crawl.run` ... always answers `unavailable / not_implemented`", and "Nine
checks" -- one day after the crawler merged and a week after the tenth check
did. All three were typed by hand and nothing compared them to anything. They
were shipped in a documentation PR whose author verified every sentence he
ADDED and none of the ones already there.

That is the same failure `test_plan_matches_repo.py` exists to prevent for
plans, and the same one S12 governs for reports: a claim about coverage goes
stale in silence, and the only defence is to derive it. `docs/DECISIONS.md`
puts it as "a report that cannot distinguish 'tested, clean' from 'never
reached' is worse than no report" -- a README that cannot distinguish "not
built" from "built last week" is the same defect aimed at a reader deciding
whether to run the thing.

These tests are deliberately few. They pin the claims that (a) a reader acts
on and (b) the code can answer for itself. Prose that is genuinely prose is
not policed here.
"""
from __future__ import annotations

import re
from pathlib import Path

import pkgutil
import importlib

from hx.checks import registry as check_registry

README = (Path(__file__).resolve().parents[1] / "README.md").read_text()

_WORDS = {9: "Nine", 10: "Ten", 11: "Eleven", 12: "Twelve", 13: "Thirteen",
          14: "Fourteen", 15: "Fifteen", 16: "Sixteen", 17: "Seventeen",
          18: "Eighteen", 19: "Nineteen", 20: "Twenty"}


def _tools():
    """Every registered tool spec, with the impl package imported first."""
    import hx.tools.impl as impl
    for m in pkgutil.iter_modules(impl.__path__):
        importlib.import_module(f"hx.tools.impl.{m.name}")
    from hx.tools.registry import TOOLS
    return TOOLS


def test_the_stated_check_count_is_the_real_one():
    """MUTATION: add or remove a check in `hx.checks.registry.CHECKS` without
    touching the README. This test must go red.

    The README said "Nine checks" for a week after the tenth shipped.
    """
    n = len(check_registry.CHECKS)
    word = _WORDS.get(n, str(n))
    assert f"**{word} checks**" in README, (
        f"the corpus has {n} checks, so the README should say "
        f"'**{word} checks**'. Update it, or teach _WORDS a bigger number."
    )


def _class_table() -> str:
    """Just the `| Class | Checks |` block, not the whole README.

    SCOPED DELIBERATELY. The first draft searched the entire file, which meant
    a check id appearing anywhere -- a limitations bullet, a worked example --
    satisfied a test whose name and docstring both promise the TABLE. It passed
    for the right reason only by accident of today's text, and would have gone
    green with the exact regression it is named for. Caught in review of the
    very PR that added it, which is its own argument for scoping.
    """
    start = README.index("| Class | Checks |")
    end = README.index("\n\n", start)
    return README[start:end]


def test_every_shipped_check_is_named_in_the_readme_table():
    """A check absent from the table is one a reader does not know they get.

    MUTATION: delete any check id from the README's class table. Must go red.

    SECOND MUTATION, and the one that matters: move a check id out of the
    table and mention it in prose elsewhere in the README. Must ALSO go red --
    it did not, before `_class_table` existed.
    """
    table = _class_table()
    missing = []
    for check in check_registry.CHECKS:
        # `hx.active.sql-behaviour` is written `sql-behaviour` in the table.
        short = check.id.rsplit(".", 1)[-1]
        if f"`{short}`" not in table:
            missing.append(check.id)
    assert not missing, f"shipped but unnamed in the README class table: {missing}"


def test_the_readme_does_not_call_a_live_tool_unimplemented():
    """THE ONE THAT ACTUALLY BIT. `crawl.run` answered
    `unavailable / not_implemented` by design for months; the README said so;
    then it shipped and the README did not change.

    Derived from the registry rather than from a list here, so the next tool
    to lose its stub is caught too.

    MUTATION: re-add "always answers `unavailable / not_implemented`" beside
    `crawl.run` in the README. Must go red.
    """
    live = sorted(n for n, s in _tools().items() if s.needs_egress)
    assert live, "fixture assumes some tool needs egress"
    for name in live:
        # Find each mention of the tool and look for a nearby unavailability
        # claim. A window, not the whole file: the README legitimately
        # discusses `unavailable` envelopes elsewhere.
        for m in re.finditer(re.escape(f"`{name}`"), README):
            window = README[m.start():m.start() + 400]
            assert "not_implemented" not in window, (
                f"the README calls `{name}` not_implemented, but it is "
                f"registered with needs_egress=True and works"
            )


def test_the_readme_does_not_claim_the_crawler_is_absent():
    """`hx crawl` is a registered CLI command and `crawl.run` is a live tool.

    MUTATION: re-add "There is no crawler yet" to the README. Must go red.
    """
    assert "crawl.run" in _tools(), "fixture assumes crawl.run is registered"
    for claim in ("no crawler yet", "There is no crawler",
                  "nothing drives a crawl"):
        assert claim not in README, (
            f"the README says {claim!r}, but the crawler ships: `hx crawl` is "
            "a CLI command and `crawl.run` is a registered tool"
        )
