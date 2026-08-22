"""The plan's code blocks must be the code, byte for byte.

This plan has drifted from the repository twice, and both times it was caught
by a human reading rather than by anything mechanical. The second time, four
fixed defects were sitting in the plan waiting to be transcribed back in, and
the commit that was supposed to prevent that claimed to "sync every code block"
while syncing six of fourteen.

A plan whose code no longer compiles is worse than no plan: implementers are
told to use its values verbatim, and reviewers byte-compare against it. So the
guarantee belongs in the suite, not in a habit.

Blocks are matched by their first line -- a `// path` or `# path` marker naming
the file. A block for a file that does not exist yet is skipped, since the plan
legitimately describes work not yet done.

A plan still being authored is a special case, and an honest one: it describes
files it has not written yet. For a file it CREATES that is handled already --
the block is skipped until the file exists. For a file it MODIFIES, the block
describes the post-implementation state while the repo still holds the previous
one, so the comparison is guaranteed to fail and says nothing useful.

Such a plan may carry `<!-- plan-drift: pending -->` near its top. Its blocks
are skipped until the marker is removed, which should happen in the commit that
finishes the plan. At most ONE plan may be pending at a time -- a test below
enforces that -- so the marker cannot quietly become the way this check is
avoided.

Deliberately NOT covered: bash blocks (`extension/build.sh`, `extension/test.sh`).
`test.sh` is legitimately staged across tasks -- Task 2 shows it running one
test class and Task 4 adds the second -- so a straight byte-compare would be
wrong there, and a staging exception is a different design than this file. If
bash blocks are ever added here, they need that exception first.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PLANS = sorted((REPO / "docs" / "superpowers" / "plans").glob("*.md"))
BLOCK = re.compile(r"```(java|python)\n(//|#) ([^\n]+)\n(.*?)```", re.S)


PENDING = "<!-- plan-drift: pending -->"


def _is_pending(plan: Path) -> bool:
    """A plan under active authoring, checked once it is finished."""
    return PENDING in "\n".join(plan.read_text().splitlines()[:40])


def _blocks():
    for plan in PLANS:
        if _is_pending(plan):
            continue
        for lang, _, path, body in BLOCK.findall(plan.read_text()):
            path = path.strip()
            if path.endswith((".java", ".py")):
                yield plan.name, path, body


def _cases():
    seen = list(_blocks())
    return [pytest.param(p, path, body, id=f"{p}::{path}") for p, path, body in seen]


@pytest.mark.parametrize("plan_name,path,body", _cases())
def test_plan_block_matches_the_file_it_names(plan_name, path, body):
    target = REPO / path
    if not target.exists():
        pytest.skip(f"{path} is not implemented yet")

    want = target.read_text().rstrip("\n")
    got = body.rstrip("\n")
    if want == got:
        return

    want_lines, got_lines = want.splitlines(), got.splitlines()
    for i, (a, b) in enumerate(zip(got_lines, want_lines), 1):
        if a != b:
            pytest.fail(
                f"{plan_name} has stale code for {path} at line {i}:\n"
                f"  plan: {a!r}\n  repo: {b!r}\n"
                f"Sync the plan from the file; never edit the block by hand."
            )
    pytest.fail(
        f"{plan_name}'s block for {path} is {len(got_lines)} lines, "
        f"the file is {len(want_lines)}. Sync the plan from the file."
    )


def test_the_check_actually_found_some_blocks():
    """A regex that silently matches nothing would make every test above vacuous."""
    assert len(_cases()) >= 10, f"only {len(_cases())} code blocks found across {PLANS}"


def test_at_most_one_plan_is_pending():
    """The escape hatch must stay an escape hatch.

    One plan being written at a time is normal. Two means the marker has become
    a way to avoid the check rather than a way to sequence it, and the plans
    that carry it are exactly the ones nobody has finished.
    """
    pending = [p.name for p in PLANS if _is_pending(p)]
    assert len(pending) <= 1, (
        f"{len(pending)} plans are marked pending: {pending}. "
        "Finish one and remove its marker before starting the next."
    )
