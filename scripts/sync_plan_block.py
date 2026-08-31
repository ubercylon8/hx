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

So this script does four things no ad-hoc version did:

  * it takes an EXPLICIT ALLOWLIST of paths. It will not touch a block you did
    not name, which is the whole of incidents 1-3.
  * it follows the FILE, not a convention. `tests/test_plan_matches_repo.py`
    re-prepends the marker line when the file itself opens with it, so the block
    body must omit that line in exactly that case. Plan 2's sources open with
    `package` / an import; Plan 3's open with `// path`. Both are legitimate;
    guessing is incident 4.
  * it VERIFIES -- by section hash, that nothing outside the sections owning
    those blocks moved, and by re-reading each block THE WAY THE PLAN CHECK
    READS IT, that the sync converged.
  * it verifies BEFORE the plan is replaced. The candidate goes to a temp file
    next to the plan, is re-read from disk, and is renamed into place only once
    every check has passed. A refusal therefore leaves the plan byte-identical:
    the previous ordering wrote first and checked second, so "refusing to leave
    this" was printed at a moment when it had already been left.

Usage:
    scripts/sync_plan_block.py PLAN TARGET [TARGET ...]

A TARGET is one of:

    src/hx/bridge/codec.py
        a WHOLE-FILE block, whose marker line is exactly that path.

    'src/hx/bridge/server.py -- halt(), the arming that comes first@573-579'
        an EXCERPT block, whose marker carries a ` -- ` note, synced from
        lines 573-579 of the file. The range is 1-based and inclusive.

The range is the operator's to supply and is not inferred. No algorithm knows
which lines "the arming that comes first" means: difflib, asked, proposed a
region for six of the eight excerpts that had drifted and garbage for the
other two, and a sync that guesses its own region is incidents 1-3 with a
different spelling. As a net against a mistyped start, a sync refuses unless
the first line of the named range is already the block's first line -- append
`!` to the range (@573-579!) to say the extent genuinely moved and you looked.

An excerpt is matched on its FULL marker, note and all: twelve blocks in Plan 3
name src/hx/bridge/server.py and differ only in that note.

Exit status is 0 when every named block is in sync and nothing else moved, and
non-zero -- with the plan untouched -- otherwise. It prints one line per target
saying whether that block changed.
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path

FENCE = "`" * 3
SECTION = re.compile(r"^(#{2,3} .*)$", re.M)

# How tests/test_plan_matches_repo.py finds a block: non-greedy to the FIRST
# fence, wherever it falls. Deliberately the same expression, because the point
# of the convergence check below is to read the candidate the way the check
# that matters will read it -- not the way this script wrote it.
BLOCK = re.compile(r"```(?:java|python|sql)\n(?://|#|--) ([^\n]+)\n(.*?)```", re.S)


# A target naming an excerpt: everything up to the last `@N-M`, which no marker
# in any plan contains. Anchored at the end so a marker may hold an `@` of its
# own -- `@body` is a real key on the wire and appears in two of these notes.
TARGET = re.compile(r"^(?P<marker>.+)@(?P<start>\d+)-(?P<end>\d+)(?P<moved>!?)$")


def _sections(text: str) -> dict[str, str]:
    """Heading -> sha256 of everything under it, for the did-anything-else-move check.

    Keyed by heading TEXT, so two identical headings in one plan would collapse
    into a single entry and a move between them would cancel out. None of the
    three plans has a duplicate heading today; if one ever does, this needs an
    index in the key. Noted rather than solved, because solving it now would be
    guessing at the shape of a plan nobody has written.
    """
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
    if path.endswith(".sql"):
        return "sql", "--"
    raise SystemExit(f"{path}: only .java, .py and .sql blocks are byte-compared")


def _as_the_plan_check_reads_it(text: str, marker_text: str) -> str | None:
    """The block marked `marker_text`, assembled exactly as the drift test assembles it.

    Matched on the WHOLE marker, note and all. Twelve blocks in Plan 3 name
    src/hx/bridge/server.py and differ only in the note after ` -- `, so a
    path-only match would read the first of the twelve back for all of them
    and report convergence for a block it had never written.
    """
    for found, body in BLOCK.findall(text):
        if found.strip() != marker_text:
            continue
        return body.rstrip("\n")
    return None


def _parse(target: str) -> tuple[str, str, tuple[int, int] | None, bool]:
    """target -> (marker text, path, line span or None for whole-file, extent-moved)."""
    m = TARGET.match(target)
    marker_text = m.group("marker") if m else target
    span = (int(m.group("start")), int(m.group("end"))) if m else None
    path = marker_text.split(" -- ")[0].strip()
    if span is None and marker_text != path:
        raise SystemExit(
            f"{marker_text}: this marker carries a ` -- ` note, so its block is an "
            "EXCERPT of the file and not the whole of it. Pasting the file over it "
            "is incident 4. Name the lines it excerpts: append @START-END."
        )
    if span and not (0 < span[0] <= span[1]):
        raise SystemExit(f"{target}: @START-END must run forwards and start at 1 or more")
    return marker_text, path, span, bool(m and m.group("moved"))


def sync(plan_path: Path, targets: list[str]) -> int:
    text = plan_path.read_text()
    before = _sections(text)
    touched: set[str] = set()
    wanted: list[tuple[str, str]] = []            # (marker text, what the check must see)
    changed = 0

    for target in targets:
        marker_text, path, span, extent_moved = _parse(target)
        src = Path(path)
        if not src.exists():
            raise SystemExit(f"{path}: no such file -- refusing to invent a block")

        lang, comment = _lang_for(path)
        marker = f"{comment} {marker_text}"
        opener = f"{FENCE}{lang}\n{marker}\n"

        n = text.count(opener)
        if n == 0:
            raise SystemExit(
                f"{marker_text}: no block in {plan_path} opens with `{marker}`, so there "
                "is nothing to sync. Check the marker line, or add the block."
            )
        if n > 1:
            raise SystemExit(
                f"{marker_text}: expected exactly one block, found {n}. "
                "Two blocks for one marker is incident 4 waiting to happen; "
                "delete the duplicate before syncing."
            )

        start = text.index(opener)
        end = text.index(f"\n{FENCE}", start + len(opener))
        was = text[start + len(opener):end]

        if span is None:
            body = src.read_text().rstrip("\n")
            # Follow the file. The drift check re-prepends the marker when the file
            # itself opens with it, so including it here would duplicate the line.
            if body.startswith(marker + "\n") or body == marker:
                body = body[len(marker):].lstrip("\n")
        else:
            lines = src.read_text().splitlines()
            first, last = span
            if last > len(lines):
                raise SystemExit(
                    f"{target}: {path} has {len(lines)} lines, so there is no line {last}."
                )
            # The net described at the top of this file. It catches a mistyped
            # start -- the one way to name a plausible but wrong region -- and
            # deliberately does NOT check the last line: a block's tail is
            # exactly where drift shows up, and two of the eight excerpts this
            # was written for had lost their final line to a fixed defect.
            head = next((line for line in was.splitlines() if line.strip()), None)
            if head is not None and lines[first - 1] != head and not extent_moved:
                raise SystemExit(
                    f"{target}: line {first} of {path} is not where this block starts.\n"
                    f"  block starts: {head!r}\n"
                    f"  {path}:{first}: {lines[first - 1]!r}\n"
                    "Check the range. If the extent genuinely moved, say so with a "
                    f"trailing `!`: @{first}-{last}!"
                )
            body = "\n".join(lines[first - 1:last])

        new = text[:start] + opener + body + text[end:]
        if new != text:
            changed += 1
            print(f"  synced    {target}")
        else:
            print(f"  unchanged {target}")
        text = new
        wanted.append((marker_text, body))

        heading = None
        for m in SECTION.finditer(text):
            if m.start() > start:
                break
            heading = m.group(1)
        if heading:
            touched.add(heading)

    # Nothing is written to the plan until every check below has passed. The
    # candidate is re-read from disk rather than trusted as the string we just
    # built -- the reason the old ordering existed -- but from a temp file, so
    # a refusal costs the plan nothing.
    tmp = plan_path.with_name(plan_path.name + ".sync-candidate")
    try:
        tmp.write_text(text)
        candidate = tmp.read_text()

        after = _sections(candidate)
        if before.keys() != after.keys():
            appeared = sorted(set(after) - set(before))
            vanished = sorted(set(before) - set(after))
            raise SystemExit(
                "a section appeared or vanished -- refusing to leave this. "
                f"appeared: {appeared}; vanished: {vanished}. A source line that "
                "starts with `## ` is read as a heading once it lands in the plan."
            )
        moved = {h for h in before if before[h] != after[h]}
        stray = moved - touched
        if stray:
            raise SystemExit(
                f"sections moved that own none of the named blocks: {sorted(stray)}. "
                "This is the incident this script exists to prevent."
            )

        # Did it converge? A source carrying a fence -- at the start of a line
        # or in the middle of one -- ends the block early for whoever reads it
        # next, so the plan check sees a different block from the one written
        # here and reports STALE run after run while this script reports
        # success. Read the candidate back the way that check reads it.
        for marker_text, body in wanted:
            got = _as_the_plan_check_reads_it(candidate, marker_text)
            if got != body:
                raise SystemExit(
                    f"{marker_text}: the block does not read back as it was written, so "
                    "the sync would never converge -- refusing. A fence inside the source "
                    "ends the block early for tests/test_plan_matches_repo.py. "
                    f"wrote {len(body.splitlines())} lines, reads back as "
                    f"{0 if got is None else len(got.splitlines())}."
                )

        os.replace(tmp, plan_path)
    finally:
        # A refusal (or a crash) must not leave a stray candidate beside the plan.
        if tmp.exists():
            tmp.unlink()

    for h in sorted(moved):
        print(f"  section moved (expected): {h[:60]}")
    return changed


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    sys.exit(0 if sync(Path(sys.argv[1]), sys.argv[2:]) >= 0 else 1)
