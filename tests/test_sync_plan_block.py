"""`scripts/sync_plan_block.py` must not leave a plan changed while refusing.

The script is the only sanctioned way to move code from a file into the plan
that quotes it, and every task on this branch now depends on it. Its own safety
checks -- "a section appeared or vanished", "sections moved that own none of
the named blocks" -- used to run *after* `plan_path.write_text(text)`, so the
message an operator saw ("refusing to leave this") was false at the moment it
was printed: the plan had already been overwritten with the text being refused.

These cases drive the real script, as a subprocess, against a throwaway plan.
They assert the plan is byte-identical after a refusal, which is the property
that separates "refused" from "refused, having already done it".
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "sync_plan_block.py"

FENCE = "`" * 3

# A miniature plan: two sections, one of which owns the only block. Built from
# a literal fence variable so this file never contains a fence of its own --
# tests/test_plan_matches_repo.py's matcher is not the only thing that stops at
# the first one it sees.
PLAN = (
    "# A throwaway plan\n"
    "\n"
    "## Task 1: the section that owns the block\n"
    "\n"
    "Prose above the block.\n"
    "\n"
    f"{FENCE}java\n"
    "// src/Thing.java\n"
    "class Thing { }\n"
    f"{FENCE}\n"
    "\n"
    "Prose below the block.\n"
    "\n"
    "## Task 2: a section that owns nothing\n"
    "\n"
    "This section must never move.\n"
)


def _fixture(tmp_path: Path, source: str) -> Path:
    plan = tmp_path / "plan.md"
    plan.write_text(PLAN)
    src = tmp_path / "src" / "Thing.java"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(source)
    return plan


def _run(tmp_path: Path, plan: Path, *targets: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(plan), *targets],
        cwd=tmp_path, capture_output=True, text=True,
    )


def test_a_clean_sync_writes_the_block_and_converges(tmp_path):
    """The control. Without it, a script that refused everything would pass."""
    plan = _fixture(tmp_path, "class Thing { int x; }\n")

    first = _run(tmp_path, plan, "src/Thing.java")
    assert first.returncode == 0, first.stdout + first.stderr
    assert "class Thing { int x; }" in plan.read_text()

    second = _run(tmp_path, plan, "src/Thing.java")
    assert second.returncode == 0, second.stdout + second.stderr
    assert "unchanged" in second.stdout, second.stdout


def test_a_refused_sync_leaves_the_plan_byte_unchanged(tmp_path):
    """A source line that markdown reads as a heading.

    `_sections()` splits on `^#{2,3} `, so this line becomes a section of its
    own the moment it lands in the plan: the key sets differ, and the script
    exits saying "refusing to leave this". The plan must not already hold it.
    """
    plan = _fixture(
        tmp_path,
        "class Thing {\n/*\n## a comment line markdown reads as a heading\n*/\n}\n",
    )
    before = plan.read_bytes()

    r = _run(tmp_path, plan, "src/Thing.java")

    assert r.returncode != 0, r.stdout + r.stderr
    assert plan.read_bytes() == before, (
        "the script refused AFTER writing: the plan holds the text it declined to accept"
    )


def test_a_source_carrying_a_fence_is_refused_rather_than_half_written(tmp_path):
    """A fence inside the source ends the block early.

    `end = text.index("\\n" + FENCE, ...)` finds the source's own fence line
    rather than the block's, so the block is truncated, the rest of the file is
    left loose as prose, and every later run finds a different `end` -- the
    sync never converges and every run still reports success. The damage sits
    inside the section that owns the block, so the section-hash check is
    silent by design. Non-convergence has to be its own refusal.
    """
    plan = _fixture(
        tmp_path,
        "class Thing {\n/*\n" + FENCE + " a fence inside the source\n*/\n}\n",
    )
    before = plan.read_bytes()

    r = _run(tmp_path, plan, "src/Thing.java")

    assert r.returncode != 0, r.stdout + r.stderr
    assert plan.read_bytes() == before, (
        "a block the plan check would read back differently was written anyway"
    )


def test_the_missing_block_message_names_the_missing_block(tmp_path):
    """Refusing correctly and explaining the opposite problem is still wrong.

    `n == 0` means the plan has no block for that path. Telling the reader to
    "delete the duplicate" sends them looking for a second block that does not
    exist.
    """
    plan = _fixture(tmp_path, "class Thing { }\n")
    other = tmp_path / "src" / "Other.java"
    other.write_text("class Other { }\n")

    r = _run(tmp_path, plan, "src/Other.java")

    assert r.returncode != 0, r.stdout + r.stderr
    message = r.stdout + r.stderr
    assert "no block" in message, message
    assert "delete the duplicate" not in message, message
