#!/usr/bin/env python3
"""Sync a plan's fenced code blocks from the files they name.

Five separate incidents on this branch came from hand-rolled versions of this
job, and they were all the same shape: the check and the thing checked drifted
apart, and the check reported green.

  1. a blind sync rewrote a FUTURE task's block from an unfinished file on disk,
     transcribing incomplete work backwards into the document meant to specify it
  2. the same, a second time
  3. an unguarded str.replace rewrote a different task's prose
  4. a script pasted the whole file under the marker line, duplicating that line
     for every source that carries its own path header -- corrupting blocks that
     were already byte-correct
  5. a harness adopted a polluted tree as its baseline, so every later restore
     verified clean against the mutation

So this script does three things no ad-hoc version did:

  * it takes an EXPLICIT ALLOWLIST of paths. It will not touch a block you did
    not name, which is the whole of incidents 1-3.
  * it follows the FILE, not a convention. `tests/test_plan_matches_repo.py`
    re-prepends the marker line when the file itself opens with it, so the block
    body must omit that line in exactly that case. Plan 2's sources open with
    `package` / an import; Plan 3's open with `// path`. Both are legitimate;
    guessing is incident 4.
  * it VERIFIES, by section hash, that nothing outside the sections owning those
    blocks moved -- and re-reads from disk to do it, rather than trusting the
    string it just built.

Usage:
    scripts/sync_plan_block.py PLAN FILE [FILE ...]

Exit status is 0 whether or not anything changed; it prints one line per file
saying which. Run it twice -- the second run must report every file unchanged,
and that is the cheapest evidence the sync converged.
"""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

FENCE = "`" * 3
SECTION = re.compile(r"^(#{2,3} .*)$", re.M)


def _sections(text: str) -> dict[str, str]:
    """Heading -> sha256 of everything under it, for the did-anything-else-move check."""
    parts = SECTION.split(text)
    out = {}
    for i in range(1, len(parts), 2):
        out[parts[i]] = hashlib.sha256(parts[i + 1].encode()).hexdigest()
    return out


def _lang_for(path: str) -> tuple[str, str]:
    if path.endswith(".java"):
        return "java", "//"
    if path.endswith(".py"):
        return "python", "#"
    raise SystemExit(f"{path}: only .java and .py blocks are byte-compared")


def sync(plan_path: Path, targets: list[str]) -> int:
    text = plan_path.read_text()
    before = _sections(text)
    touched: set[str] = set()
    changed = 0

    for path in targets:
        src = Path(path)
        if not src.exists():
            raise SystemExit(f"{path}: no such file -- refusing to invent a block")

        lang, comment = _lang_for(path)
        marker = f"{comment} {path}"
        opener = f"{FENCE}{lang}\n{marker}\n"

        n = text.count(opener)
        if n != 1:
            raise SystemExit(
                f"{path}: expected exactly one block, found {n}. "
                "Two blocks for one file is incident 4 waiting to happen; "
                "delete the duplicate before syncing."
            )

        start = text.index(opener)
        end = text.index(f"\n{FENCE}", start + len(opener))

        body = src.read_text().rstrip("\n")
        # Follow the file. The drift check re-prepends the marker when the file
        # itself opens with it, so including it here would duplicate the line.
        if body.startswith(marker + "\n") or body == marker:
            body = body[len(marker):].lstrip("\n")

        new = text[:start] + opener + body + text[end:]
        if new != text:
            changed += 1
            print(f"  synced    {path}")
        else:
            print(f"  unchanged {path}")
        text = new

        heading = None
        for m in SECTION.finditer(text):
            if m.start() > start:
                break
            heading = m.group(1)
        if heading:
            touched.add(heading)

    plan_path.write_text(text)

    # Re-read from disk rather than trusting the string we just built.
    after = _sections(plan_path.read_text())
    if before.keys() != after.keys():
        raise SystemExit("a section appeared or vanished -- refusing to leave this")
    moved = {h for h in before if before[h] != after[h]}
    stray = moved - touched
    if stray:
        raise SystemExit(
            f"sections moved that own none of the named blocks: {sorted(stray)}. "
            "This is the incident this script exists to prevent."
        )
    for h in sorted(moved):
        print(f"  section moved (expected): {h[:60]}")
    return changed


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    sys.exit(0 if sync(Path(sys.argv[1]), sys.argv[2:]) >= 0 else 1)
