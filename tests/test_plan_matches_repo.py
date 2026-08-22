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


def _blocks():
    for plan in PLANS:
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
