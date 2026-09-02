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

One entry left that list on 2026-08-23 by being FIXED rather than re-argued.
Two blocks in Plan 3 were marked `added to ...BridgeClientTest.java, called from
main()`, and the exception said no contiguous run of the file equalled either.
That was true of one of them and not the other. Step 7's block holds two methods
with a later task's test now between them in the repo, so it is two excerpts, and
it is now two blocks with a sentence between them saying why. Step 16's block is
one contiguous run of 173 lines and always was -- it was merely stale, four
`l.reader.read()` calls that have since been given a deadline -- so it is one
excerpt. All three are compared here now, which took this check from 78 blocks to
81. (Counted with `len(_cases())`. The pytest line for this file reads 86, which is
81 plus the five tests below that are not parametrised over blocks -- an easy pair of
numbers to confuse, and this wave confused them once already.)

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
compared above. The other was Task 3's Step 9, which quoted a `Policy.Rule.matches`
shape the file no longer had -- the authority comparison was split out into
`authorityMatches`, so the step could not be performed as written. A sync could not
have fixed that: the sabotage names a line to change, and the line had moved. It was
rewritten against the current file and re-measured the same day -- one FAIL, the one
the step names -- and it stays outside this check, because a sabotage block is the
state AFTER a mutation and byte-comparing it to the file is exactly backwards.

Deliberately NOT covered: bash blocks (`extension/build.sh`, `extension/test.sh`).
`test.sh` is legitimately staged across tasks -- Task 2 shows it running one
test class and Task 4 adds the second -- so a straight byte-compare would be
wrong there, and a staging exception is a different design than this file. If
bash blocks are ever added here, they need that exception first.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

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


# The real number, not a floor.
#
# This assertion was `>= 10` until 2026-08-24, against 81 blocks actually
# found. Seventy-one of them could have stopped being compared -- a regex that
# matched one plan instead of three, a marker convention that moved,
# `_names_a_file` getting stricter, a ````java` fence becoming ```` ```jav ````
# -- and this test, whose entire job is to notice that the check stopped
# looking, would have gone on passing with 8x margin to spare. A floor that far
# below the truth is the same silence the rest of this file exists to remove.
#
# UPDATE THIS NUMBER in the commit that adds or removes a marked block, and say
# which block in the message. Marking a plan `<!-- plan-drift: pending -->`
# drops its blocks from the count and will also turn this red: that is
# intended, not collateral. A pending plan is a plan whose blocks are NOT being
# compared, and how many stopped being compared should be a decision somebody
# wrote down rather than a number that quietly moved.
#
# 139 = 115 from five earlier plans, plus 24 the active-checks plan contributed
# on 2026-08-29 when its blocks were marked and synced against the shipped
# code. It had contributed ZERO until then -- every one of its fences went
# unmarked -- which is precisely the silence this constant exists to price.
# 2026-08-27-checks-and-reporting.md is still `pending` and still contributes
# none of its 26, and that is a merged plan: worth fixing, and a bigger job
# than marking one.
#
# 141 = 139 plus the TWO the identity plan contributed on 2026-08-30, when Task
# 1 shipped `src/hx/config.py`'s identity declaration and its tests and synced
# both blocks against the code. The rest of that plan's fences are deliberately
# unmarked: they specify files Tasks 2-8 have not written yet, and a marker on
# a block whose file does not exist is a comparison against nothing. Markers go
# on at the END of a plan's execution, which is the same rule the active-checks
# plan followed above.
#
# Writing that plan is what taught this: its first commit added fourteen marked
# blocks at once and turned this suite red before a line of the feature was
# written. The marker line is inside the fence, so any fenced Python whose
# first line is a comment becomes a tracked block whether or not anyone meant
# it to be.
# 183 = 167 plus the SIXTEEN the egress plan contributes on 2026-08-31, the day
# it was written and before any of it was built. Every one of the sixteen names
# a file that plan CREATES -- `src/hx/issue.py`, `src/hx/delta.py`,
# `src/hx/tools/live.py`, `src/hx/tools/impl/http.py`, `.../impl/scan.py`,
# `.../adapters/mcp.py`, `src/hx/http_text.py` and their nine test files -- so
# all sixteen are SKIPPED here today and arm themselves one at a time as the
# tasks land. That is the same shape the tool-layer plan had (29 skips falling
# back to 1) and it is why marking a creation block early is safe where marking
# a MODIFICATION block early is not: a block for a file that does not exist is
# skipped, and a block for a file that does is compared against the version
# before the change and fails.
#
# The number moves HERE, in the commit that adds the plan, precisely because
# the paragraph above says the active-checks plan turned this suite red by
# adding fourteen markers without moving it. Moving it deliberately is the
# decision this constant exists to make somebody write down.
#
# 229 = 183 plus the FORTY-SIX the web-app-foundation plan contributes on
# 2026-09-01, the day its six tasks were finished and the plan was armed for
# closing. All forty-six compare against code that already exists, unlike
# the egress plan's sixteen above -- this wave marks at the END of a plan's
# execution, the ordinary case the rule at 341 describes. They are:
#   Task 1 (3): `tests/test_coverage.py` split across its two writing
#     steps; `src/hx/run.py`'s `stale_before_us`/`is_stale` and its rewritten
#     `reap_stale`, two excerpts since Task 1's own docstring fix (below)
#     sits between them.
#   Task 2 (7): `tests/test_triage.py` and `src/hx/triage.py` whole;
#     `tests/test_cli_triage.py` whole; three excerpts of `src/hx/cli.py`
#     and `src/hx/report.py` for the `triage` command and its import; the
#     dismissed/confirmed report tests appended to `tests/test_report.py`;
#     `src/hx/report.py`'s `_status()`.
#   Task 3 (10): `tests/test_web_registry.py`, `src/hx/web/registry.py`,
#     `tests/test_web_security.py` and `src/hx/web/render.py` whole; the web
#     fixtures in `tests/conftest.py`; `src/hx/web/reads.py` through
#     `overview()`; `src/hx/cli.py`'s `web` command; the overview screen
#     tests; and `src/hx/web/app.py`'s Step 11 block, split into FOUR
#     excerpts (imports-through-CSP, `hostname`/`_secured`, `_guard`
#     through `overview`, `create_app`) because Task 6 lands
#     `_form_fields`/`_same_origin` and its constants in the middle of what
#     was one contiguous block when Task 3 wrote it -- the same shape as
#     the Interface Contract split noted at the top of this file.
#   Task 4 (6): the surfaces/findings screen tests; `SEVERITIES`,
#     `STATUSES` and `FilterError`, and `surfaces()`/`findings()`, in
#     `src/hx/web/reads.py`; the matching pair in `src/hx/web/app.py`; and
#     their two routes.
#   Task 5 (6): `tests/test_credentials_never_reach_the_screen.py` whole;
#     the finding/exchange screen tests; the evidence-chain reads appended
#     to `src/hx/web/reads.py`; `finding()`/`exchange()` in
#     `src/hx/web/app.py`; and their two routes.
#   Task 6 (10): `tests/test_web_writes.py` whole (294 lines today, not the
#     197 Step 1 wrote -- a later fix round extended it and this block now
#     tracks the current file); the import block, `SAFE_METHODS`/
#     `MAX_FORM`/`_TOO_LARGE`, `_form_fields()`, `_same_origin()`, the
#     cross-site branch inside `_guard`, `triage_post()`/`halt_post()`,
#     their two routes and the halt banner added to `overview()`, all in
#     `src/hx/web/app.py`.
# `src/hx/run.py`'s `is_stale` docstring is the one place this wave went
# the other way: the plan already had the corrected paragraph explaining
# `started_us if heartbeat_us is None else heartbeat_us` over `heartbeat_us
# or started_us`, and `run.py` was fixed to match the plan rather than the
# plan synced down to the stale code -- so that block reads "unchanged"
# above, not "synced".
EXPECTED_BLOCKS = 229


def test_the_check_actually_found_some_blocks():
    """A regex that silently matches nothing would make every test above vacuous."""
    found = len(_cases())
    assert found == EXPECTED_BLOCKS, (
        f"{found} code blocks found across {[p.name for p in PLANS]}, "
        f"expected {EXPECTED_BLOCKS}. If a block was deliberately added or "
        "removed, update EXPECTED_BLOCKS in the same commit and name the block "
        "in the message. If it was not, the check has stopped looking at "
        f"{EXPECTED_BLOCKS - found} of them."
    )


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


# A method declaration inside a `NOT_A_FILE` sketch: modifiers, a return type,
# a name, an open paren. Deliberately anchored to the indentation the sketches
# use, so a line of prose in a comment cannot look like one.
_SKETCH_METHOD = re.compile(
    r"^    (?:public|protected)(?: static| final| synchronized| abstract)* "
    r"[\w.<>\[\], ]+? (\w+)\(", re.M)


def test_no_java_sketch_declares_a_method_that_exists_nowhere():
    """The Interface Contract's `Redactor` block declared three signatures the
    shipped class never had, and the block called itself the source of truth.

    None of these markers names a file, so the byte comparison above never
    looked -- a package sketch spanning four classes has nothing to be
    compared to. That is still true, and this is the part of it that CAN be
    checked: a method the sketch names must exist somewhere in extension/src.
    `clear()` did not exist anywhere in the tree, which is what this would
    have caught.

    WHAT IT DOES NOT SEE, said plainly rather than left to be discovered: it
    matches on NAME only. The same block's `redactRequest(byte[] raw)` has a
    real name and the wrong arity, and `register(...)` is real but lives on
    `Injected` rather than on `Redactor` -- neither is visible here. The
    defence against those is the precedence sentence in the block itself,
    which now says the CODE is right when the two disagree; this test is the
    cheap half, not the whole of it.
    """
    java = "\n".join(p.read_text(encoding="utf-8")
                     for p in sorted((REPO / "extension" / "src").rglob("*.java")))
    missing: list[tuple[str, str]] = []
    checked = 0
    for plan in PLANS:
        if _is_pending(plan):
            continue
        for lang, prefix, marker, body in BLOCK.findall(plan.read_text()):
            if lang != "java" or marker.strip() not in NOT_A_FILE:
                continue
            for name in _SKETCH_METHOD.findall(body):
                checked += 1
                if f"{name}(" not in java:
                    missing.append((marker.strip(), name))
    assert checked > 10, (
        f"only {checked} sketch declarations were parsed; the regex stopped "
        "matching and this test is now vacuous")
    assert missing == [], (
        "these Interface Contract signatures name methods that exist nowhere "
        f"in extension/src: {missing}. The CODE is right -- fix the block."
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


def test_every_workflow_is_a_workflow():
    """Six of eleven workflows shipped unparseable, and every check I ran passed.

    `gh api ... > file` captured mise's tool-activation banner as the FIRST
    LINE of each file it fetched, so six workflows began `mise
    ~/.config/mise/config.toml tools: gh@2.98.0` and GitHub answered "this run
    likely failed because of a workflow file issue" for every one of them.

    WHAT MAKES THIS WORTH A TEST is what it survived. zizmor reported no
    findings on all eleven; a grep confirmed none still said `branches:
    [main]`; another counted `branches: [master]` in nine. Every one of those
    passed because it searched for CONTENT, and the content was all there --
    one junk line above it. Nothing asked the only question that mattered:
    does this file parse as a workflow?

    AND THE FIRST VERSION OF THIS TEST DID NOT CATCH IT EITHER. Asserting
    "parses as a mapping with `jobs` and a `name`" passes with the banner in
    place, because YAML reads `mise ~/.config/mise/config.toml tools:
    gh@2.98.0` as a perfectly ordinary KEY AND VALUE. The file is still a
    mapping; it just has one key GitHub has never heard of. A test written for
    a bug, that the bug walks straight through, is the same failure one level
    up -- so this asserts the TOP-LEVEL KEY SET instead, which is the thing
    the junk line actually changes.

    `on` is read via both spellings because PyYAML resolves the bare word `on`
    to the boolean True (the Norway-problem family), which is itself the kind
    of thing a content grep cannot see.
    """
    root = Path(__file__).resolve().parents[1] / ".github" / "workflows"
    files = sorted(root.glob("*.yml"))
    assert len(files) >= 11, f"expected the eleven workflows, found {len(files)}"
    for path in files:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(doc, dict), (
            f"{path.name} is not a YAML mapping -- a stray first line (a shell "
            f"banner, a fetch artefact) turns the whole file into a scalar")
        assert "jobs" in doc, f"{path.name} declares no jobs"
        assert "on" in doc or True in doc, f"{path.name} declares no trigger"
        assert doc.get("name"), f"{path.name} has no name"
        # The set GitHub accepts at the top of a workflow. `True` is `on`
        # after PyYAML has resolved it. Anything else means a line that is not
        # part of the workflow got into the file -- which is precisely what
        # happened, and what "is it a mapping" could not see.
        allowed = {"name", "run-name", "on", True, "permissions", "env",
                   "defaults", "concurrency", "jobs"}
        stray = sorted(str(k) for k in doc if k not in allowed)
        assert not stray, (
            f"{path.name} has top-level key(s) GitHub does not accept: "
            f"{stray}. A stray first line -- a shell banner, a fetch artefact "
            f"-- parses as an ordinary key and leaves the file a valid "
            f"mapping, so it reaches GitHub as 'a workflow file issue'")
