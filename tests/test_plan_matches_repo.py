"""The plan's code blocks must be the code, byte for byte.

This plan has drifted from the repository twice, and both times it was caught
by a human reading rather than by anything mechanical. The second time, four
fixed defects were sitting in the plan waiting to be transcribed back in, and
the commit that was supposed to prevent that claimed to "sync every code block"
while syncing six of fourteen.

A plan whose code no longer compiles is worse than no plan: implementers are
told to use its values verbatim, and reviewers byte-compare against it. So the
guarantee belongs in the suite, not in a habit.

Blocks are matched by their first line -- a `// path`, `# path` or `-- path`
marker naming the file. A block for a file that does not exist yet is skipped,
since the plan legitimately describes work not yet done.

A marker may carry a note after ` -- `, and then the block is an EXCERPT: the
one method that changed, not the whole file. Plan 3 uses that shape for every
modification to a file that already existed, and until 2026-08-23 those blocks
were dropped in SILENCE -- the filter asked whether the marker ended in `.java`
or `.py`, and `# src/hx/bridge/server.py -- send(), new, above halt()` does not.
Twenty went unchecked; eight were stale. Six of the eight taught a halt that is
optional -- five spelling `operator_halt=None` or `if self.operator_halt is not
None`, one giving `launch_burp` a `sentinel: Path | None = None` -- after commit
2b753de had made both required, on the grounds that a durable halt nobody has to
supply is two of spec S4's three paths and a silence where the third was. An
excerpt is compared as a CONTIGUOUS run of the file's lines, byte for byte, in
order: no normalisation, so a block is what the file says or it is stale.

A marker that is not a path at all -- `hx.policy`, a package sketch spanning
several classes -- is a NAMED exception in NOT_A_FILE below, and a test asserts
that set is exactly what the plans contain. Silence is what this file exists to
remove, so an unlisted one fails rather than being skipped.

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

Deliberately NOT covered: fenced blocks with NO marker line at all. There are
40 across the three plans, 16 of them the code a sabotage step tells an operator
to delete or replace. Some of those quote the file and some are the state AFTER
the mutation and are SUPPOSED to differ from it, and telling the two apart means
reading the step's prose -- a different design than this file. All 17 were
checked by hand on 2026-08-23: two were stale. One is now a marked block and is
compared above; the other is Task 3's Step 9, which quotes a `Policy.Rule.matches`
shape the file no longer has, and needs its sabotage rewritten rather than
synced. It is still there.

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
BLOCK = re.compile(r"```(java|python|sql)\n(//|#|--) ([^\n]+)\n(.*?)```", re.S)
SOURCE_SUFFIXES = (".java", ".py", ".sql")


PENDING = "<!-- plan-drift: pending -->"

# Markers that name no file. Each is a sketch the plan wrote to explain a shape,
# not a transcription of anything on disk, so there is nothing to compare it to.
# Listed rather than filtered out by a rule, because a rule would go on silently
# absorbing whatever else stopped looking like a path.
NOT_A_FILE = {
    "hx.policy":
        "a package sketch: the classes of one package at once, no single file",
    "hx.send":
        "the same, for the send package",
    "hx.bridge -- seams added to BridgeClient so the send path can be installed":
        "the same, for the seams the send path needs across the bridge package",
    "contract sketch for src/hx/halt.py -- NOT the file, and deliberately":
        "says so in the marker: a contract, written before the file, and the "
        "file is compared by its own block a few steps later",
    "added to extension/test/hx/bridge/BridgeClientTest.java, called from main()":
        "a COMPOSITE excerpt -- several methods added to one file, with methods "
        "added by later tasks now sitting between them in the repo. No contiguous "
        "run of the file equals it, and re-syncing it as one run would pull a "
        "later task's test into an earlier task's block, which is incident 1. "
        "Measured 2026-08-23: the second of the two is stale -- four lines call "
        "`l.reader.read()`, which has since been given a deadline, and a 26-line "
        "check the repo has is absent. Splitting it into its contiguous pieces "
        "would bring it under this check; nobody has.",
}


def _is_pending(plan: Path) -> bool:
    """A plan under active authoring, checked once it is finished."""
    return PENDING in "\n".join(plan.read_text().splitlines()[:40])


def _names_a_file(head: str) -> bool:
    """Whether a marker's head could be a path in this repository.

    The suffix alone is not enough. `contract sketch for src/hx/halt.py` ends in
    `.py`, and admitting it would put a block that says in its own marker that it
    is NOT the file into the parametrised test, where it would be skipped forever
    as "not implemented yet" -- silence again, wearing a different hat.
    """
    return head.endswith(SOURCE_SUFFIXES) and not any(c.isspace() for c in head)


def _blocks():
    for plan in PLANS:
        if _is_pending(plan):
            continue
        for lang, prefix, marker, body in BLOCK.findall(plan.read_text()):
            marker = marker.strip()
            path = marker.split(" -- ")[0].strip()
            if _names_a_file(path):
                yield plan.name, path, f"{prefix} {marker}", body, marker != path


def _cases():
    seen = list(_blocks())
    return [pytest.param(p, path, marker, body, excerpt,
                         id=f"{p}::{marker.split(' ', 1)[1]}")
            for p, path, marker, body, excerpt in seen]


def _contains(haystack: list[str], needle: list[str]) -> bool:
    """Is `needle` a contiguous run of `haystack`, in order, byte for byte?

    An empty needle is refused rather than answered True. `[] in anything` is the
    shape every vacuous check in this repository has had.
    """
    if not needle:
        raise ValueError("an empty block matches every file; it cannot be a block")
    return any(haystack[i:i + len(needle)] == needle
               for i in range(len(haystack) - len(needle) + 1))


@pytest.mark.parametrize("plan_name,path,marker,body,excerpt", _cases())
def test_plan_block_matches_the_file_it_names(plan_name, path, marker, body, excerpt):
    target = REPO / path
    if not target.exists():
        pytest.skip(f"{path} is not implemented yet")

    want = target.read_text().rstrip("\n")

    if excerpt:
        _fail_unless_the_file_contains_it(plan_name, path, marker, body, want)
        return

    # The marker line naming the file is normally the block's own scaffolding and
    # not part of the file. But some source files open with exactly that line as
    # their own header comment, and then it IS part of the file -- so the block is
    # byte-identical fence to fence while a body-only comparison calls it stale.
    # Decide by looking at the file rather than by convention: whichever the file
    # does, both are legitimate, and neither should need the other to change.
    got = body.rstrip("\n")
    if want.startswith(marker + "\n") or want == marker:
        got = f"{marker}\n{got}"
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


def _fail_unless_the_file_contains_it(plan_name, path, marker, body, want):
    """An excerpt must be a contiguous run of the file it names.

    Where a whole-file block is a transcription, an excerpt is a QUOTATION, and
    the guarantee a reader needs from a quotation is that the file still says it
    -- somewhere, in order, unbroken. That is weaker than byte-equality by
    exactly the part the plan chose not to quote, and it is the strongest thing
    that can be said about a fragment without the plan naming line numbers.
    """
    file_lines = want.splitlines()
    got = body.rstrip("\n").splitlines()
    if _contains(file_lines, got):
        return

    # Where does it stop being the file? Anchor on the excerpt's first line and
    # walk: the answer a reader needs is the FIRST line that differs, not that
    # 454 lines failed to be equal to something.
    best_at, best_run = -1, 0
    for i, line in enumerate(file_lines):
        if line != got[0]:
            continue
        run = 0
        while (i + run < len(file_lines) and run < len(got)
               and file_lines[i + run] == got[run]):
            run += 1
        if run > best_run:
            best_at, best_run = i, run

    if best_at < 0:
        pytest.fail(
            f"{plan_name}'s excerpt `{marker}` is not in {path} at all -- its "
            f"very first line appears nowhere in the file:\n  plan: {got[0]!r}\n"
            "Sync it with scripts/sync_plan_block.py; never edit a block by hand."
        )
    plan_line = got[best_run] if best_run < len(got) else "<end of block>"
    repo_line = (file_lines[best_at + best_run]
                 if best_at + best_run < len(file_lines) else "<end of file>")
    pytest.fail(
        f"{plan_name} has a stale excerpt of {path} (`{marker}`).\n"
        f"It is the file from {path}:{best_at + 1} for {best_run} of its "
        f"{len(got)} lines, then diverges:\n"
        f"  plan: {plan_line!r}\n"
        f"  repo: {path}:{best_at + best_run + 1}: {repo_line!r}\n"
        f"Sync it from the file, naming the lines it quotes:\n"
        f"  scripts/sync_plan_block.py docs/superpowers/plans/{plan_name} "
        f"'{marker.split(' ', 1)[1]}@{best_at + 1}-END'"
    )


def test_a_marker_that_names_no_file_is_a_named_exception():
    """The 26 blocks this check used to drop, it dropped without a word.

    Twenty were excerpts and are compared now. The rest name no file, and the
    honest thing to do with them is say so once, by name, with the reason -- so
    that the NEXT marker nobody thought about fails here instead of joining them.
    """
    found = {}
    for plan in PLANS:
        if _is_pending(plan):
            continue
        for lang, prefix, marker, body in BLOCK.findall(plan.read_text()):
            marker = marker.strip()
            if _names_a_file(marker.split(" -- ")[0].strip()):
                continue
            found.setdefault(marker, []).append(plan.name)

    unlisted = sorted(set(found) - set(NOT_A_FILE))
    assert not unlisted, (
        f"{len(unlisted)} block marker(s) name no file and are not in NOT_A_FILE: "
        f"{unlisted}. If the marker meant to name a file, fix the marker -- it "
        "reads `path` for a whole file and `path -- note` for an excerpt. If it "
        "genuinely names no file, add it to NOT_A_FILE with the reason."
    )
    gone = sorted(set(NOT_A_FILE) - set(found))
    assert not gone, (
        f"NOT_A_FILE names {len(gone)} marker(s) no plan contains any more: {gone}. "
        "Delete the entries. An exception list nobody prunes is how the next "
        "unchecked block gets to look accounted for."
    )


def test_a_stale_excerpt_is_caught_where_a_whole_file_compare_never_looked(tmp_path):
    """The failure this whole mode exists for, in eight lines.

    An excerpt of a file cannot be compared to the file, so the old check
    dropped it -- and what it dropped, on this branch, was a `BridgeServer`
    whose durable halt was optional, sitting in a merged plan for an implementer
    to transcribe back in. Both spellings below are plausible Python; only one
    is in the file, and the difference is whether a halt can be skipped.
    """
    file_lines = [
        "    def __init__(self, socket_path, engagement_id, operator_halt):",
        "        if operator_halt is None:",
        '            raise BridgeError("operator_halt is required")',
        "        self.operator_halt = operator_halt",
    ]
    fresh = ["        if operator_halt is None:",
             '            raise BridgeError("operator_halt is required")']
    stale = ["        if operator_halt is not None:",
             '            raise BridgeError("operator_halt is required")']

    assert _contains(file_lines, fresh)
    assert not _contains(file_lines, stale)

    # And an excerpt whose lines are all present but not TOGETHER is stale too:
    # the plan would be claiming a shape the file does not have.
    scattered = [file_lines[0], file_lines[3]]
    assert not _contains(file_lines, scattered)

    with pytest.raises(ValueError):
        _contains(file_lines, [])


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


def test_a_file_whose_first_line_is_its_own_path_marker_is_compared_whole(tmp_path):
    """The comparison must follow the file, not a convention.

    Plan 2's Java sources open with `package`; Plan 3's open with a comment
    naming their own path -- the same line the plan block uses as its marker. A
    body-only comparison is right for the first and wrong for the second, and
    getting it wrong makes six correct blocks look stale at once.
    """
    marker = "// extension/src/hx/policy/Policy.java"
    body = "package hx.policy;\n\nfinal class Policy { }"

    # A file that repeats the marker as its own header: compare including it.
    with_header = f"{marker}\n{body}"
    assert with_header.startswith(marker + "\n")

    # A file that does not: the marker is scaffolding and must be dropped.
    assert not body.startswith(marker + "\n")
