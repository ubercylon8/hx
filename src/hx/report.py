"""One Markdown file: the deliverable.

S12 is specific and this module does exactly what it says and no more -- one
file, in the structure already delivered by hand, not a format x audience
matrix.

THE COVERAGE SECTION IS THE POINT. Findings are what a client reads first and
what any tool can produce. What makes a report honest is the part that says
which checks ran with which verdicts, and (via `_coverage`'s `Surfaces`
column) how many distinct surfaces each answer covers, AND -- F2 of fix round
B -- how many surfaces the engagement captured in the first place and which
of them nothing ever answered for. A count with no denominator and no surface
named cannot answer "did you test the password reset flow?", which is the
question S12 gives as the reason this section exists; the "Never tested" list
is the half that can. S12: a report that cannot distinguish "tested,
clean" from "never reached" is worse than no report.

PROVENANCE COMES FROM THE STORE, NEVER FROM `config`. S12's other
requirement -- "The report cites `scope_version.sha256` and the
`authorization` record in force, so what you were permitted to touch is part
of the deliverable" -- was unimplemented until F4 of fix round B: `render`
selected `engagement.created_us` and dropped it, and the Scope section
iterated TODAY's `config.yaml`, which is a different object from the scope
that was in force when the traffic was captured. `_provenance` reads
`engagement.created_us`, the `run` window, every `scope_version` row with its
hash and the runs stamped to it, and the `authorization` table -- which no
code path in this repository writes, so the section says that in as many
words rather than being omitted and reading as though a record existed.

REDACTION RUNS ON EXPORT, THROUGH ONE FUNCTION: `_redact`. Fix round 1, F1 of
the review found this docstring claiming redaction "runs over everything
rendered" while `records.redact_url` was called at exactly one site (the
evidence URL) -- title, description, impact, remediation and the coverage
table's `reason` cell all reached the export raw. `reason` is not a marginal
vector: `hx.scan` builds it as `f"{type(exc).__name__}: {exc}"`
(`scan.py:163`), an exception message that can quote a response body or a
request target, so it is attacker-influenced by construction. Every field
below that can carry a URL -- a finding's title, description, impact and
remediation, an evidence URL, a coverage reason, a run's `stop_reason`, a
scope version's `author` and `reason`, AND (fix round 2, R1) every
`scope.include`/`scope.exclude` PATTERN -- is routed through `_redact`
before it reaches `out`. The Scope section was the one place F1's own fix
missed: an operator can paste a credential straight into a scope pattern
(`https://user:pass@app.test/*`), and until R1 that string reached the
export verbatim, unredacted, because it is operator-authored rather than
something a check or the scan wrote -- but S12 draws no such exception, and
neither does `_redact`. F10 (fix round B) closed the two that were left:
`engagement.client`, which is the document's own TITLE, and
`engagement.name` on the line under it -- both straight off `hx new`'s
command line, both as operator-authored as a scope pattern, and the review
named only the first. `check_id`, severity, confidence, verdict, status
and cwe are controlled vocabularies fixed by the schema's own CHECK
constraints; they never carry a URL and are not passed through it.

`_redact` (and the `records.redact_url` it wraps) only removes the userinfo
and credential-parameter VALUES of the FIRST authority/query it finds in a
string (`records._userinfo_cuts`, `records._credential_param_cuts` -- both a
single `str.find`, not a scan for every occurrence). A field that embedded
two distinct URLs, the second carrying the credential, would still leak the
second through this choke point. That is a property of `redact_url` itself,
inherited here rather than reintroduced, and untested by this module because
fixing it belongs to `records.py`.
"""
from __future__ import annotations

import datetime
import hashlib

from hx import config as config_mod
from hx import insertion as insertion_mod
from hx.checks import registry
from hx.store import records
from hx.store.blobs import CorruptBlob

_ORDER = ("Critical", "High", "Medium", "Low", "Info")

# The chain grows one row per genuine capture, across every run that ever
# saw the finding -- `records.record_evidence`'s own docstring says so and
# says explicitly that bounding what gets RENDERED is this module's job, not
# the writer's: "a finding seen in fifty runs holds fifty evidence rows...  a
# report must not print fifty rows for one problem." Each row is a distinct
# exchange with its own id (`record_exchange` mints a fresh one per capture),
# so there is no key to dedupe on here either -- the rows are all genuine.
#
# Five is enough to show the shape of the chain (first appearance, and that
# it recurred) without the report turning into an exchange dump. The bound is
# STATED when it bites, never a silent truncation: a reader who needs the
# full chain still has it -- every row this caps is still sitting in
# `evidence`, unbounded, exactly as `record_evidence` left it.
_EVIDENCE_LIMIT = 5

# How many never-tested surfaces the Coverage section NAMES before it
# summarises, on the same rule as `_EVIDENCE_LIMIT`: capped, and the cap
# STATED when it bites, never a silent truncation. Twenty rather than five
# because this list is the ACTIONABLE set -- "here is what we did not test"
# is the sentence a client acts on, and a browse-heavy engagement routinely
# leaves a dozen surfaces behind the last scan.
_UNTESTED_LIMIT = 20

# How many DISTINCT reasons one coverage row prints before it says how many
# more there were. See `_coverage` for why the table no longer groups on the
# reason itself.
_REASON_LIMIT = 2

# The `check_run.verdict` values that mean a check actually produced an
# answer about a surface, and therefore that the surface was REACHED.
#
# `pending` is excluded because S5 says what it is for in as many words: "a
# 'pending' row is written BEFORE the check runs, so a crash leaves evidence
# that the surface was never reached". `skipped` is excluded because it is
# the runner saying the check never ran -- `hx.scan._skip_rest` writes it
# when a budget cuts a scan off -- and `hx.checks.base`'s own docstring puts
# `pending`, `skipped` and `error` on the runner's side of exactly S12's
# distinction. `error` IS included: the check reached the surface and raised,
# which is a failure to answer rather than a failure to arrive, and the row
# renders in the table as `error` where a reader can see no clean answer was
# obtained.
_ANSWERED = ("clean", "finding", "inconclusive", "error")


def _redact(text) -> str | None:
    """The one choke point every rendered string that might carry a URL
    passes through. `None` in, `None` out -- callers still decide whether an
    absent field is worth a line."""
    if text is None:
        return None
    return records.redact_url(str(text))


def _flat(value) -> str:
    """Free text on ONE line, whatever it arrived carrying.

    A newline ends a Markdown table row outright and ends a bullet just as
    finally, so every rendered free-text value is flattened -- not only the
    ones that reach a table. Split out of `_cell` by F2 of fix round B,
    which put free text (a surface's `method` and `path_template`) into
    BULLETS for the first time: `_cell`'s `|` escaping is right for a table
    cell and wrong inside a code span, where `\\|` renders as two literal
    characters.
    """
    if value is None:
        return ""
    return (str(value).replace("\r\n", " ").replace("\n", " ")
           .replace("\r", " "))


def _cell(value) -> str:
    """A Markdown table cell, safe against the free text that can reach one.

    `check_run.reason` is exception text and can contain `|` (which splits a
    cell in two, silently absorbing everything after it into the next
    column) or a newline (which ends the table row outright, and everything
    after it renders as loose text or a broken second row). Escaped, never
    dropped -- the text still matters even when it is inconvenient to a
    table. Applied to every column of the coverage table, not only the ones
    known to carry free text today: `check_id` and `verdict` are controlled
    vocabularies now, and a guard that only fires where the current writer
    happens to be careless is not a guard.
    """
    if value is None:
        return ""
    return _flat(value).replace("\\", "\\\\").replace("|", "\\|")


def _when(us) -> str:
    """A stored microsecond timestamp as a UTC instant a client can read.

    Every timestamp in this schema is "integer microseconds since epoch"
    (`schema.sql`'s own opening line), and none of them is rendered anywhere
    until F4. UTC with an explicit `Z`, never local time: the deliverable is
    read by people in other timezones than the one it was rendered in, and a
    naive local timestamp in a contractual document is a fact nobody can
    check afterwards.
    """
    if us is None:
        return "unknown"
    return datetime.datetime.fromtimestamp(
        us / 1_000_000, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _by_class() -> tuple[tuple, tuple]:
    """This build's checks, split into `(passive, active)`.

    F5 (fix round B). `_limits` and `_insertion_coverage` hardcoded three
    sentences -- "None were probed", "this build ships no active checks",
    "Every check in this build is passive" -- in a module that ALREADY
    derives its unshipped-class note from `registry.CHECKS` two functions
    away. The first entry of Plan 6's active corpus makes all three false in
    a client deliverable, with no test to redden: the Limits section would
    tell a client no request carrying a payload was ever issued while
    `check_run.requests_sent` said otherwise, and the passive-retest
    disclosure added in fix round 2 -- true only while every shipped check is
    passive -- would decay in the same silence.

    READ AT CALL TIME, not captured at import, for the same reason the
    unshipped-class note reads `registry.CHECKS` at call time: the corpus is
    the authority for these sentences, and a module-level snapshot taken at
    import is a second one that can disagree with it.

    `klass != "passive"` rather than a list of the four active class names.
    `registry.KNOWN_CLASSES` is S10's five and `registry.validate` refuses
    anything outside it at import, so a check that is not passive is active
    by construction -- INCLUDING a class S10 has not named yet, which a
    hardcoded list of names would silently file as passive and re-open this
    exact defect.
    """
    checks = tuple(registry.CHECKS)
    return (tuple(c for c in checks if c.klass == "passive"),
            tuple(c for c in checks if c.klass != "passive"))


def _names(checks) -> str:
    """A comma-separated list of check ids, for a sentence that names them.

    `check_id` is a controlled vocabulary fixed by the registry (`validate`
    refuses a duplicate, and every id in this build is a literal in a check
    class), so it needs neither `_redact` nor `_cell` -- the same reason the
    coverage table's `check_id` column does not get them.
    """
    return ", ".join(f"`{c.id}`" for c in checks)


def render(conn, *, engagement_id, config, blobs=None) -> str:
    out: list[str] = []
    eng = conn.execute(
        "SELECT id, name, client, created_us FROM engagement WHERE id=?",
        (engagement_id,)).fetchone()

    # F10 (fix round B): the title's client name and the line under it --
    # `engagement.client` and `engagement.name` -- were the last two rendered
    # free-text fields still reaching the export raw. Standing ruling R1: text
    # an OPERATOR authored is not exempt from redaction, because S12 draws no
    # such exception and neither does `_redact`. `hx new --client` takes a
    # string off the command line, and a credential pasted into it (the same
    # way one reaches a scope pattern, which R1 was about) reached the title
    # of the client deliverable verbatim. The review named `client` alone as
    # "the last free-text rendered field"; `name` is rendered raw on the very
    # next line and is exactly as operator-authored, so both move.
    out.append(f"# {_redact(eng[2])} — web application assessment\n")
    out.append(f"Engagement `{_redact(eng[1])}`.\n")

    # ONE SOURCE OF TRUTH FOR "HAS THIS ENGAGEMENT EVER BEEN SCANNED",
    # shared by `_findings` (F4 of fix round 1: an unscanned engagement's
    # "None recorded" must not read as a clean bill) and `_coverage` (the
    # original "not been scanned" paragraph). Computed once here rather than
    # twice, differently, in two functions that would otherwise be free to
    # quietly disagree.
    scanned = bool(conn.execute(
        "SELECT 1 FROM check_run cr JOIN run r ON r.id = cr.run_id"
        " WHERE r.engagement_id=? LIMIT 1", (engagement_id,)).fetchone())

    # F8 (fix round B), and computed here for the same reason `scanned` is:
    # several sections make a statement about it and none may be free to
    # disagree with the others. `_provenance` NAMES the runs that did not
    # finish; `_coverage` marks its own numbers partial because of them; and
    # -- N2 of fix round C -- `_findings` qualifies "None recorded" with them,
    # exactly as it already qualifies it with `scanned`.
    unfinished = _unfinished_runs(conn, engagement_id)

    out.extend(_provenance(conn, engagement_id, config, created_us=eng[3],
                           unfinished=unfinished))
    out.extend(_findings(conn, engagement_id, scanned=scanned,
                         unfinished=unfinished))
    out.extend(_coverage(conn, engagement_id, config, scanned=scanned,
                         unfinished=unfinished))
    if blobs is not None:
        out.extend(_insertion_coverage(conn, engagement_id, blobs))
    out.extend(_limits(conn, engagement_id))
    return "\n".join(out) + "\n"


def _unfinished_runs(conn, engagement_id) -> list[tuple]:
    """Every run behind this report that did not end `completed`.

    F8 (fix round B). Nothing in this module read `run.status` or
    `run.stop_reason`, and S5 says what that costs, of `run` itself:

        an aborted run must never render as a clean one, and neither must
        one that merely STOPPED BEING UPDATED: a run left `running` with a
        stale heartbeat_us is a run whose harness died, and it resolves to
        `error`, not `completed`.

    A scan stopped by Ctrl-C, by a `sqlite3.Error` through `cli.scan`'s
    `except`-less `try`/`finally`, or by a stale-heartbeat reap rendered its
    partial coverage byte-identically to a complete pass. The abort path is
    reachable today, and this is S12's governing rule again: a report that
    cannot distinguish "tested, clean" from "never reached" is worse than no
    report, and half a run is exactly the second thing wearing the first
    thing's clothes.

    `status <> 'completed'` rather than a list of the bad values, so all four
    of `running | aborted | killed | error` are caught and a value added to
    the CHECK constraint later cannot slip through as finished. `running` is
    included deliberately: S5's own sentence says a run left running is a
    dead harness, and a run genuinely still in flight while the report
    renders has produced partial coverage too.
    """
    return conn.execute(
        "SELECT id, kind, status, stop_reason, started_us FROM run"
        " WHERE engagement_id=? AND status <> 'completed'"
        " ORDER BY started_us, id", (engagement_id,)).fetchall()


def _provenance(conn, engagement_id, config, *, created_us,
                unfinished) -> list[str]:
    """When this engagement ran, what it was permitted to touch, and on whose
    authority -- read from the STORE.

    F4 (fix round B). S12, in the sentence this function exists for:

        Redaction runs on export. The report cites `scope_version.sha256`
        and the `authorization` record in force, so what you were permitted
        to touch is part of the deliverable.

    None of it was here. `render` selected `engagement.created_us` and threw
    it away, and the whole Scope section iterated `config.scope_include` /
    `config.scope_exclude` -- TODAY's `config.yaml`, which is not the same
    object as the scope that was in force when the traffic was captured. The
    data was all there and simply unwired: `scope_version` is append-only
    under two triggers and described in `schema.sql` as "tamper-evidence for
    contract disputes", `run.scope_version_id` is the column that WOULD stamp
    each run with the version it ran under -- nothing in this build writes
    it, which is why the `Runs` column reads 0 on every store this build
    produces and why `_scope_of_record` says so from the store's own numbers
    rather than from a claim about the build -- and `authorization` has held
    a place for the signed permission since Plan 1. (N5 of fix round B's
    re-review: this docstring asserted the stamp as settled fact a hundred
    lines above a comment that correctly denied it. The code was right and
    the docstring was what a future reader would have trusted.)

    EVERY VERSION, OLDEST FIRST, NOT JUST THE LATEST. A second row means the
    boundary MOVED mid-engagement, which is the one case the append-only
    table exists for -- S5: "The one query that matters under dispute is
    'what was in scope when request X was issued', and it must be
    answerable." Rendering only the newest as though it had always been the
    boundary answers that query wrongly, and silently. The `Runs` column is
    how the table answers it at the grain this store actually records:
    `run.scope_version_id` per row.

    THE PATTERNS ARE STILL READ FROM `config`, AND THE CLAIM MADE ABOUT THEM
    IS CHECKED RATHER THAN ASSUMED. `scope_version.yaml` holds the config
    text verbatim (`engagement._record_scope` hashes exactly what
    `config.dumps` produced), so re-hashing the config this render was handed
    says whether it IS the newest recorded version or merely today's file.
    `engagement.open_` already refuses to open a store where the two diverge,
    so through `hx report` the answer is yes -- but `render` takes `config`
    as a free parameter, so the check is what makes the sentence above the
    patterns true of every caller rather than of one. Parsing each historical
    version's yaml back into patterns is deliberately NOT done here: that
    would put a second reader of the config format in this module, and the
    hash plus the version's own metadata is what S12 asks the report to cite.

    THE AUTHORIZATION RECORD IS ABSENT AND SAYS SO. Nothing in this
    repository writes an `authorization` row -- the table is declared in
    `schema.sql`, named in `db.py`'s expected-table set, and written by no
    code path in `src/`, `extension/` or `tests/`. A client deliverable that
    simply omitted the section would read as though a record existed and had
    been left out; saying it plainly is the only honest rendering, and
    writing one is a later plan's job, not this fix's.
    """
    out = ["## Provenance\n",
           f"Engagement opened {_when(created_us)}.\n"]

    # N4 (fix round C): `MAX(COALESCE(ended_us, started_us))` printed a still
    # OPEN run's START as the window's end, under a sentence promising that
    # "nothing outside it was observed" -- false by construction, because
    # traffic captured after that instant is in this report and more is
    # arriving while it renders. Reachable by the ordinary loop: browse in one
    # terminal, `hx report` in another.
    #
    # The window is now read as three separate facts and no fourth is
    # invented: how many runs, the earliest start, the latest RECORDED end
    # (`MAX(ended_us)` ignores NULLs, so it is a real end or nothing at all),
    # and how many runs have no end on record. S12's governing rule is that a
    # report which cannot distinguish two states is worse than no report, and
    # "this assessment ended at T" and "this assessment has not ended" are two
    # states -- COALESCE collapsed the second into the first. Widening the
    # window to the render clock was the other candidate and is rejected for
    # the same rule: `_when` renders stored microseconds, and a wall-clock
    # instant nothing in the store holds would be a fourth fact, invented at
    # render time, in the one section S12 asks to be read FROM THE STORE.
    runs = conn.execute(
        "SELECT COUNT(*), MIN(started_us), MAX(ended_us),"
        " SUM(CASE WHEN ended_us IS NULL THEN 1 ELSE 0 END),"
        " SUM(CASE WHEN ended_us IS NULL AND status = 'running'"
        "          THEN 1 ELSE 0 END)"
        " FROM run WHERE engagement_id=?", (engagement_id,)).fetchone()
    total_runs, first_us, last_end_us, endless, in_flight = runs
    if total_runs and not endless:
        out.append(f"{total_runs} run(s) recorded, the earliest starting "
                   f"{_when(first_us)} and the latest ending "
                   f"{_when(last_end_us)}. "
                   "That window is the assessment: nothing outside it was "
                   "observed, and this report says nothing about the "
                   "application before or after it.\n")
    elif total_runs:
        # `MAX(ended_us)` skips the NULLs, so this is a real recorded end or
        # nothing -- never a start wearing an end's label. `last_end_us is
        # None` is exactly the case where EVERY run is endless (a run with an
        # end would have supplied one), so the two spellings do not overlap.
        span = ("**Not one of them has a recorded end.**"
                if last_end_us is None else
                f"**{endless} run(s) here carry no recorded end**, and the "
                f"latest run that did end ended {_when(last_end_us)}.")
        # The two endings are DIFFERENT FACTS and the report must not merge
        # them. A run still `running` means the window is open and growing;
        # a run that stopped without an end being written means the close is
        # simply unknown. Only the first justifies "traffic is still
        # arriving", and only the store can say which this is.
        tail = (" **This assessment window is therefore still open**: "
                f"{in_flight} of those runs had not ended when this report "
                "was rendered, so traffic captured after it — including "
                "traffic arriving while it was being written — falls inside "
                "the window too."
                if in_flight else
                " Nothing here establishes when observation stopped, so this "
                "window must not be quoted as a closed one.")
        out.append(f"{total_runs} run(s) recorded, the earliest starting "
                   f"{_when(first_us)}. {span}{tail} Nothing before that "
                   "earliest start was observed, and this report says "
                   "nothing about the application before it.\n")
    else:
        out.append("**No run has been recorded for this engagement.** "
                   "Nothing below was observed by this tool.\n")

    if unfinished:
        out.append(f"**{len(unfinished)} of those runs did not finish.** "
                   "Everything this report draws from them is what they had "
                   "reached when they stopped, not what a completed run "
                   "would have produced.\n")
        for run_id, kind, status, stop_reason, started_us in unfinished:
            line = (f"- run `{_flat(run_id)}` ({_flat(kind)}, started "
                    f"{_when(started_us)}) ended `{_flat(status)}`")
            if stop_reason:
                # `stop_reason` is free text and attacker-influenceable:
                # `hx.scan.run` writes `f"scan.run raised: {type(exc).__name__}:
                # {exc}"`, an exception message that can quote a request
                # target. Through `_redact` like every other such field.
                line += f" — stop reason: {_flat(_redact(stop_reason))}"
            else:
                line += " and recorded no stop reason"
            out.append(line)
        out.append("")

    out.extend(_scope_of_record(conn, engagement_id, config))
    out.extend(_authorization(conn, engagement_id))
    return out


def _scope_of_record(conn, engagement_id, config) -> list[str]:
    versions = conn.execute(
        "SELECT sv.sha256, sv.effective_from_us, sv.author, sv.reason,"
        " (SELECT COUNT(*) FROM run r WHERE r.scope_version_id = sv.id)"
        " FROM scope_version sv WHERE sv.engagement_id=?"
        " ORDER BY sv.effective_from_us, sv.rowid", (engagement_id,)).fetchall()

    out = ["### Scope of record\n"]
    digest = hashlib.sha256(
        config_mod.dumps(config).encode("utf-8")).hexdigest()

    if versions:
        out.append(f"{len(versions)} scope version(s) are on file, in the "
                   "order they took effect. The table is append-only and "
                   "cannot be rewritten, so a second row means the boundary "
                   "MOVED during the engagement and traffic captured before "
                   "it was governed by the row above.\n")
        out.append("| Effective from (UTC) | `scope_version.sha256` |"
                   " Author | Runs | Reason |")
        out.append("|---|---|---|---|---|")
        for sha256, effective_us, author, reason, run_count in versions:
            out.append(f"| {_when(effective_us)} | `{_cell(sha256)}` |"
                       f" {_cell(_redact(author))} | {run_count} |"
                       f" {_cell(_redact(reason))} |")
        out.append("")
        unstamped = conn.execute(
            "SELECT COUNT(*) FROM run WHERE engagement_id=?"
            " AND scope_version_id IS NULL", (engagement_id,)).fetchone()[0]
        if unstamped:
            # A client seeing 0 in the `Runs` column beside "2 run(s)
            # recorded" two paragraphs above reads a contradiction, and the
            # report has to say which absence the 0 is -- the same reason the
            # authorization section states its own absence rather than being
            # omitted.
            #
            # N1 (fix round C). This used to say "Nothing in this build
            # writes that link", which is a claim about the BUILD, typed
            # rather than derived, and exactly the defect F5 was raised for
            # one section further down. The trigger is scheduled: the day a
            # plan stamps `run.scope_version_id`, a genuine `Runs` count of 0
            # -- no run under that version -- would still be declared "a
            # missing record and not an absence of runs", with nothing to
            # redden.
            #
            # Both numbers below are read off THIS STORE, and the claim is
            # read off THE TABLE JUST RENDERED: `shown` is the sum of the
            # `Runs` column a reader can see. When it is 0 the strong
            # sentence is provable from the page itself; when it is not, the
            # sentence that fires says only what is true of a partly stamped
            # store. A writer landing later moves this text by moving the
            # data, and when every run is stamped `unstamped` is 0 and none
            # of it renders at all.
            total_runs = conn.execute(
                "SELECT COUNT(*) FROM run WHERE engagement_id=?",
                (engagement_id,)).fetchone()[0]
            shown = sum(v[4] for v in versions)
            how_many = (f"All {total_runs} run(s) recorded for this "
                        "engagement carry"
                        if unstamped == total_runs else
                        f"{unstamped} of the {total_runs} run(s) recorded "
                        "carry")
            out.append(
                f"{how_many} no `scope_version_id`, so which of the rows "
                "above was in force for them cannot be read off this store. "
                + ("Every `Runs` count above is 0 for that reason alone: it "
                   "is a missing link, not an absence of runs.\n"
                   if shown == 0 else
                   f"The `Runs` column above accounts for {shown} run(s), so "
                   "a 0 in a row means no STAMPED run named that version.\n"))

    if versions and digest == versions[-1][0]:
        out.append("The patterns below are the newest version in that table, "
                   f"`{digest}` — verified, not assumed: the configuration "
                   "this report was rendered from hashes to that row.\n")
    elif versions:
        out.append("**The patterns below are NOT the scope of record.** They "
                   "are the configuration this report was rendered from, and "
                   f"it hashes to `{digest}`, which matches no row above. "
                   "Read the boundary off the recorded versions.\n")
    else:
        out.append("**No scope version is recorded for this engagement.** "
                   "The patterns below are the configuration this report was "
                   f"rendered from (`{digest}`); nothing in this store "
                   "establishes that they were the boundary when the traffic "
                   "was captured.\n")

    for pattern in config.scope_include:
        out.append(f"- `{_redact(pattern)}`")
    for pattern in config.scope_exclude:
        out.append(f"- excluded: `{_redact(pattern)}`")
    out.append("")
    return out


def _authorization(conn, engagement_id) -> list[str]:
    rows = conn.execute(
        "SELECT signatory, doc_sha256, valid_from_us, valid_to_us,"
        " scope_sha256 FROM authorization WHERE engagement_id=?"
        " ORDER BY valid_from_us, rowid", (engagement_id,)).fetchall()
    out = ["### Authorization\n"]
    if not rows:
        # N1 (fix round C). This used to add "Nothing in this build writes
        # one, so this is true of every engagement it produces" -- a claim
        # about the BUILD, typed rather than derived, with nothing that
        # reddens when it stops being true. Unlike the `Runs` count above,
        # there is no store fact to derive it from: an empty `authorization`
        # table looks identical whether no writer exists or an operator
        # simply recorded no document. So the claim is not made. The trigger
        # is scheduled -- a later plan wires the writer the rendered-row
        # branch below was built for -- and on that day this sentence would
        # have told every client whose operator recorded nothing that the
        # TOOL cannot record it, converting an operator's omission into an
        # apparent tool limitation. That is the direction that EXCUSES a
        # missing authorisation record, which is the one direction a
        # deliverable must not lean in.
        #
        # What is left is read entirely off the query above: the table is
        # empty, and the conservative reading of an empty table is the one a
        # client is given. It stays true under every future build.
        out.append("**No authorization record is on file for this "
                   "engagement.** The `authorization` table in this store "
                   "holds no row for it: the client's written permission, if "
                   "any was given, is held outside this store and is not "
                   "part of this deliverable. Read nothing above as evidence "
                   "that testing was authorised.\n")
        return out
    out.append("| Valid from (UTC) | Valid to (UTC) | Signatory |"
               " `doc_sha256` | `scope_sha256` |")
    out.append("|---|---|---|---|---|")
    for signatory, doc_sha256, valid_from_us, valid_to_us, scope_sha256 in rows:
        out.append(f"| {_when(valid_from_us)} | {_when(valid_to_us)} |"
                   f" {_cell(_redact(signatory))} | `{_cell(doc_sha256)}` |"
                   f" `{_cell(scope_sha256)}` |")
    out.append("")
    return out


def _latest_observed(conn, finding_id) -> bool | None:
    """Whether the most recent `finding_observation` row for this finding --
    the most recent RUN whose owning check actually tested its surface --
    says the finding is still there.

    F9 (fix round 1, the one the reviewer cared most about even at MEDIUM):
    `finding_observation` carries the exact datum Tasks 5 and 6 spent three
    fix rounds making correct -- `observed=0` is, in `scan.py`'s own words,
    "the exact datum a retest renders as fixed" -- and until this fix
    nothing in this module ever read it. A finding gone as of the latest
    scan rendered byte-identical to a live one, which tells a client
    something untrue in the direction they will act on: re-flagging and
    re-remediating a problem that is already gone.

    Returns `None` when the finding has never been retested (found once,
    never checked again) -- distinct from `False`. S12's distinction between
    "tested, clean" and "never reached" applies here too: a finding with no
    second data point has not been confirmed EITHER live or fixed, and
    presenting `None` as `False` would manufacture a fact this store does
    not have.

    Ordered by the RUN's own `started_us`, not `finding_observation.ts_us`:
    a run's wall-clock start is the ordering the rest of this schema treats
    as authoritative for "which happened later" (the same reason
    `finding.last_seen_run` tracks a run id and not a raw timestamp), and it
    is stable under a write retried inside one run in a way a write-time
    timestamp is not.

    R2 (fix round 2): this is the most recent run WHOSE OWNING CHECK ACTUALLY
    TESTED the finding's surface -- a run that skipped the check, errored on
    it, or never scanned this surface at all writes no `finding_observation`
    row and is invisible to this query, correctly. The caller-facing marker
    used to say "the most recent run", which is a different and sometimes
    FALSE claim: a finding fixed in run 2, with run 3 skipping its check
    entirely, is still reported here off run 2 -- correct -- but "the most
    recent run" read as if it meant run 3, which never tested it. The
    wording at the call site was corrected to say what this function
    actually computes.
    """
    row = conn.execute(
        "SELECT fo.observed FROM finding_observation fo"
        " JOIN run r ON r.id = fo.run_id WHERE fo.finding_id=?"
        " ORDER BY r.started_us DESC, fo.ts_us DESC LIMIT 1",
        (finding_id,)).fetchone()
    if row is None:
        return None
    return bool(row[0])


def _findings(conn, engagement_id, *, scanned, unfinished) -> list[str]:
    # `ORDER BY title, id`: F13 of fix round 1. Without an ORDER BY, two
    # renders of the same store can list one severity's findings in a
    # different order -- SQLite makes no promise about it -- and a retest
    # diff fills with reordering noise that is not a real change. `id` is
    # the tiebreak for two findings sharing a title.
    rows = conn.execute(
        "SELECT id, title, severity, confidence, description, impact,"
        " remediation, cwe, status FROM finding WHERE engagement_id=?"
        " ORDER BY title, id",
        (engagement_id,)).fetchall()
    if not rows:
        if not scanned:
            # F4: the same claim `cli.py`'s `scan` command already refuses
            # to make to an operator ("no surfaces captured yet" is a
            # different fact from "0 findings") -- a client reading an
            # unqualified "None recorded" above a "not been scanned"
            # Coverage section reads it as a clean bill it never earned.
            return ["## Findings\n",
                   "None recorded — this engagement has not been scanned "
                   "yet; see Coverage below.\n"]
        if unfinished:
            # N2 (fix round C), and the same qualifier pattern F4 established
            # one branch up. MEASURED on an `aborted` run: this section
            # emitted `## Findings` / `None recorded.`, BYTE-IDENTICAL to what
            # a complete, genuinely clean scan emits. S5 is categorical --
            # "an aborted run must never render as a clean one" -- and
            # Findings is the section this module's own docstring says a
            # client reads first. Coverage below already marks its numbers
            # partial, so the information was in the document; the part read
            # first did not carry it.
            return ["## Findings\n",
                   f"None recorded — but {len(unfinished)} of the runs behind "
                    "this report did not finish (each is named under "
                    "Provenance above), so this is not a clean bill: a check "
                    "a stopped run never got to cannot have found anything. "
                    "See Coverage below for what was and was not reached.\n"]
        return ["## Findings\n", "None recorded.\n"]

    out = ["## Findings\n"]
    if unfinished:
        # The same defect in the other direction, and the same fix: a LIST of
        # findings drawn from runs that stopped renders byte-identically to
        # one drawn from a completed pass, and reads as the whole of what
        # there was. S5's rule is about the run, not about the emptiness of
        # the list.
        out.append(f"**{len(unfinished)} of the runs behind this report did "
                   "not finish** (each is named under Provenance above), so "
                   "what follows is what they had reached when they stopped, "
                   "not what a completed run would have found.\n")
    by_sev = {s: [r for r in rows if r[2] == s] for s in _ORDER}
    for severity in _ORDER:
        if not by_sev[severity]:
            continue
        # F13: `### {severity}` nests the severity group UNDER `## Findings`
        # rather than beside it -- it used to be `##`, a sibling of every
        # top-level section rather than a child of this one.
        out.append(f"### {severity}\n")
        for r in by_sev[severity]:
            fid, title, _sev, confidence, desc, impact, fix, cwe, status = r
            # `####`, one level deeper again, to stay a grandchild of
            # `## Findings` now that the severity group moved to `###`.
            out.append(f"#### {_redact(title)}\n")
            marker = ""
            observed = _latest_observed(conn, fid)
            if observed is False:
                marker = (" · **not observed the last time its check "
                          "tested this surface — appears fixed; verify "
                          "before closing**")
            out.append(f"*Confidence: {confidence}*"
                       + (f" · *{cwe}*" if cwe else "")
                       + (f" · *status: {status}*" if status != "new" else "")
                       + marker
                       + "\n")
            for label, text in (("", desc), ("**Impact.** ", impact),
                                ("**Remediation.** ", fix)):
                if text:
                    out.append(f"{label}{_redact(text)}\n")
            out.extend(_evidence(conn, fid))
    return out


def _evidence(conn, finding_id) -> list[str]:
    rows = conn.execute(
        "SELECT e.seq, x.method, x.url, x.status FROM evidence e"
        " LEFT JOIN exchange x ON x.id = e.exchange_id"
        " WHERE e.finding_id=? ORDER BY e.seq", (finding_id,)).fetchall()
    if not rows:
        return []
    out = ["**Evidence.**\n"]
    total = len(rows)
    shown = rows[:_EVIDENCE_LIMIT]
    unresolved = 0
    for _seq, method, url, status in shown:
        if url is None:
            # F6: `evidence.exchange_id` is nullable and the LEFT JOIN
            # anticipates a row this schema allows but no writer produces
            # today (a note/ref-only entry) -- this row has already
            # consumed one of the five slots in `shown`. It must be
            # counted as unresolved, not silently dropped: dropping it
            # made "1 bullet, 3 further evidence rows omitted, first 5 of
            # 8" claim eight rows accounted for when only four were.
            unresolved += 1
            continue
        status_text = status if status is not None else "no status recorded"
        out.append(f"- `{method} {_redact(url)}` → {status_text}")
    omitted = total - len(shown)
    caveats = []
    if omitted > 0:
        # STATED, not silent -- see `_EVIDENCE_LIMIT`. `total`, not
        # `len(shown)`: the true count in the store, pinned by
        # `test_a_long_evidence_chain_states_the_true_total`.
        #
        # F11 (fix round B): "observation(s)" collided with
        # `finding_observation`, which is this schema's word for PRESENCE PER
        # RUN -- the datum `_latest_observed` reads and the retest
        # deliverable is built from. A reader who has just been told a
        # finding "was not observed the last time its check tested this
        # surface" takes "5 of 8 observations" as eight RUNS, and the two
        # numbers are unrelated: `evidence` rows are exchanges, accumulated
        # across every run that ever saw the finding, and a single run
        # routinely contributes several. "evidence row(s)" is what these
        # are, and it cannot be read as the other thing.
        caveats.append(f"{omitted} further evidence row(s) omitted (this "
                       f"chain is capped at the first {_EVIDENCE_LIMIT} of "
                       f"{total})")
    if unresolved > 0:
        caveats.append(f"{unresolved} of the {len(shown)} shown could not "
                       "be resolved to a request")
    if caveats:
        out.append("- … " + "; ".join(caveats) +
                   ". Every evidence row is still recorded in the store.")
    out.append("")
    return out


def _coverage(conn, engagement_id, config, *, scanned, unfinished) -> list[str]:
    """Which checks answered for which surfaces, and -- F2 of fix round B --
    which surfaces nothing answered for.

    THE TABLE ALONE CANNOT ANSWER "WHAT DID YOU NOT TEST?". It was four
    columns of counts with no surface named in any of them and no
    denominator anywhere, under a sentence promising that "a surface absent
    from this table was never reached". No surface was ever IN the table, so
    the promise was unfalsifiable, and the everyday sequence that breaks it
    is not exotic: browse, scan, browse more, report. Every surface captured
    after the last scan vanished from coverage in silence. MEASURED by the
    review: ten captured surfaces with one scanned rendered as four
    `clean 1` rows and no note. This section now states the denominator and
    NAMES the surfaces nothing answered for, which is the set a client acts
    on.

    THE TABLE GROUPS ON (check_id, verdict), NOT ON `reason`. It used to
    group on the reason too, which was harmless only while a reason was a
    short controlled word (`budget`). F6 of the previous round made a
    passive check's `inconclusive` reason NAME THE UNREADABLE EXCHANGE IDS
    -- `_http._detail`, "x-9f3a: outcome=timeout; x-11c4: no response was
    stored" -- so two surfaces failing the same way for different exchanges
    no longer group, and the table gained a row per surface and stopped
    being a summary. `check_id` and `verdict` are controlled vocabularies
    fixed by the registry and by `check_run`'s own CHECK constraint, so
    grouping on them alone bounds the table at corpus x 6 rows however much
    free text the reason column carries; grouping on attacker-influenced
    text let one string per surface multiply rows without bound. The reason
    stays ACTIONABLE by being carried into the row it belongs to: the
    distinct reasons under a (check, verdict), commonest first, capped at
    `_REASON_LIMIT` with the remainder counted -- the same cap-and-say-so
    rule `_evidence` and `_http._detail` already use.
    """
    captured = conn.execute(
        "SELECT COUNT(*) FROM surface WHERE engagement_id=?",
        (engagement_id,)).fetchone()[0]
    untested = _untested_surfaces(conn, engagement_id)

    out = ["## Coverage\n"]
    if unfinished:
        # F8: coverage drawn from a run that did not finish is coverage of
        # what that run reached before it stopped. Said HERE as well as in
        # Provenance because this is the section whose numbers are affected,
        # and a reader who scrolled straight to it must not take them for a
        # complete pass.
        out.append(f"**These numbers are partial.** {len(unfinished)} of the "
                   "runs behind this section did not finish (each is named "
                   "under Provenance above), so a check that never opened "
                   "for a surface may simply be a check the run never got "
                   "to.\n")
    if captured:
        out.append(f"This assessment captured **{captured} surface(s)**. "
                   f"**{captured - len(untested)}** had at least one check "
                   f"return a verdict; **{len(untested)}** had none.\n")
    else:
        out.append("**No surface was captured for this engagement**, so "
                   "there is nothing here for a check to have covered.\n")

    if not scanned:
        out.append("This engagement has **not been scanned**. No check has run "
                   "against any surface, so nothing below should be read as "
                   "tested.\n")
    else:
        # F5: `COUNT(DISTINCT cr.surface_id)`, not `COUNT(*)`. A `check_run`
        # row exists per (surface, check) PER RUN (`scan.py`'s `_open_row`
        # writes `surface_id` on every row it opens, including a skipped
        # one), so `COUNT(*)` over rows grouped by (check, verdict, reason)
        # counts a retested surface once per run it was retested in --
        # three surfaces scanned twice rendered "6". The error is always
        # upward, the one direction a coverage figure must not lie in.
        rows = conn.execute(
            "SELECT cr.check_id, cr.verdict, COUNT(DISTINCT cr.surface_id)"
            " FROM check_run cr"
            " JOIN run r ON r.id = cr.run_id WHERE r.engagement_id=?"
            " GROUP BY cr.check_id, cr.verdict"
            " ORDER BY cr.check_id, cr.verdict", (engagement_id,)).fetchall()
        reasons = _reasons_by_row(conn, engagement_id)

        out.append("Which checks ran, against how many distinct surfaces "
                   "each, and what they answered — one row per check and "
                   "verdict. This table COUNTS surfaces and does not name "
                   "them; the surfaces no check answered for are named "
                   "below it.\n")
        out.append("| Check | Verdict | Surfaces | Reason |")
        out.append("|---|---|---|---|")
        for check_id, verdict, n in rows:
            out.append(f"| `{_cell(check_id)}` | {_cell(verdict)} | {n} |"
                       f" {_reason_cell(reasons.get((check_id, verdict), []))} |")
        out.append("")

    # F11: a check CLASS the operator disabled, or one this build ships
    # nothing for, leaves no `check_run` row and so no trace in the table
    # above -- `hx scan` already tells the operator this at the terminal
    # (`cli.py`'s own "enabled but this build ships no checks in it" note);
    # the durable artifact must say the same thing, not less. Outside the
    # `scanned` branch on purpose: it is a fact about the build and this
    # engagement's config, true whether or not a scan has ever run.
    unshipped = sorted(
        klass for klass, on in config.checks.items()
        if on and not any(c.klass == klass for c in registry.CHECKS))
    for klass in unshipped:
        out.append(f"- note: `{klass}` is enabled in this engagement's "
                   "config, but this build ships no checks in that class — "
                   "nothing above is coverage for it.")
    if unshipped:
        out.append("")

    # LAST IN THE SECTION, and after the unshipped notes rather than before
    # them: these are bullets too, and a blank line between two bullet lists
    # is not a separation a reader sees. The notes qualify the TABLE and
    # belong beside it; the untested list is the section's conclusion, and
    # putting the notes under it made them read as three more untested
    # surfaces.
    out.extend(_untested(untested))
    return out


def _untested_surfaces(conn, engagement_id) -> list[tuple]:
    """Every captured surface no check ever returned a verdict for.

    NOT "no `check_run` row": see `_ANSWERED`. A surface whose only rows are
    `pending` (the runner opened them and the process died) or `skipped`
    (the budget cut the scan off before them) was never actually tested, and
    counting either as coverage is S12's failure in the direction that
    matters -- reading a row that exists to record a gap as though it
    recorded an answer.

    `method` + `path_template` is the surface's readable identity, the same
    pair `_insertion_coverage` selects and the same one `surface`'s own
    UNIQUE constraint builds identity from. Ordered by template then method
    so two renders of one store cannot differ, for the reason `_findings`
    has an `ORDER BY`.
    """
    marks = ",".join("?" for _ in _ANSWERED)
    return conn.execute(
        "SELECT s.method, s.path_template FROM surface s"
        " WHERE s.engagement_id=? AND NOT EXISTS ("
        "   SELECT 1 FROM check_run cr JOIN run r ON r.id = cr.run_id"
        "   WHERE cr.surface_id = s.id AND r.engagement_id = s.engagement_id"
        f"    AND cr.verdict IN ({marks}))"
        " ORDER BY s.path_template, s.method, s.id",
        (engagement_id, *_ANSWERED)).fetchall()


def _untested(untested) -> list[str]:
    if not untested:
        return []
    out = [f"**Never tested.** These {len(untested)} surface(s) were "
           "captured and no check ever returned a verdict for them — a "
           "`pending` or `skipped` row is not coverage. A surface named "
           "here was **never reached**, which is not the same as clean.\n"]
    shown = untested[:_UNTESTED_LIMIT]
    for method, path_template in shown:
        # `_redact` is identity for a path template -- there is no `://` in
        # one for `records.redact_url` to find an authority behind -- and it
        # is applied anyway, because the rule is that every free-text field
        # rendered here passes the choke point, not that each caller argues
        # its own field safe.
        out.append(f"- `{_flat(method)} {_flat(_redact(path_template))}`")
    omitted = len(untested) - len(shown)
    if omitted:
        out.append(f"- … {omitted} further surface(s) omitted (this list is "
                   f"capped at the first {_UNTESTED_LIMIT} of "
                   f"{len(untested)}). Every one is still recorded in the "
                   "store.")
    out.append("")
    return out


def _reasons_by_row(conn, engagement_id) -> dict:
    """The distinct `check_run.reason` values under each (check, verdict),
    commonest first.

    Ordered by how many surfaces recorded each reason, then by the reason
    text -- so the one a reader most needs is the one that survives
    `_REASON_LIMIT`, and the tiebreak is stable across renders.
    """
    out: dict = {}
    for check_id, verdict, reason, _surfaces in conn.execute(
            "SELECT cr.check_id, cr.verdict, cr.reason,"
            " COUNT(DISTINCT cr.surface_id) AS n FROM check_run cr"
            " JOIN run r ON r.id = cr.run_id WHERE r.engagement_id=?"
            " AND cr.reason IS NOT NULL AND cr.reason <> ''"
            " GROUP BY cr.check_id, cr.verdict, cr.reason"
            " ORDER BY cr.check_id, cr.verdict, n DESC, cr.reason",
            (engagement_id,)).fetchall():
        out.setdefault((check_id, verdict), []).append(reason)
    return out


def _reason_cell(reasons) -> str:
    shown = reasons[:_REASON_LIMIT]
    cell = "; ".join(_cell(_redact(r)) for r in shown)
    omitted = len(reasons) - len(shown)
    if omitted:
        cell += f"; and {omitted} further distinct reason(s)"
    return cell


def _insertion_coverage(conn, engagement_id, blobs) -> list[str]:
    """Insertion points derived from what was captured, and not probed.

    S4 of the design doc says why this exists: body and parameter insertion
    points are DERIVED AND RECORDED even though this build probes none of
    them, so the coverage section can say `this parameter exists and was not
    probed` rather than leaving the reader to assume it was covered.

    DERIVED AT RENDER TIME, not stored -- S5 is explicit that there is no
    insertion table in v1, and a derivation is a derivation whenever it runs.
    """
    rows = conn.execute(
        "SELECT s.path_template, s.method, x.req_blob FROM surface s"
        " LEFT JOIN exchange x ON x.id = s.exemplar_exchange_id"
        " WHERE s.engagement_id=? ORDER BY s.path_template",
        (engagement_id,)).fetchall()
    counted: dict[str, int] = {}
    for _template, _method, req_blob in rows:
        if not req_blob:
            continue
        try:
            raw = blobs.get(req_blob)
        except CorruptBlob:
            # F8: narrowed from a bare `except Exception`, which used to
            # swallow `blobs.get`'s own `AttributeError` when a caller
            # passed `blobs=None` past the `render()` guard -- making the
            # guard's removal unobservable (14 tests still passed). A
            # missing or digest-mismatched blob is an expected, per-row
            # failure this loop already tolerates by skipping the row;
            # anything else -- including a caller's own programming error
            # -- is meant to surface.
            continue
        for point in insertion_mod.derive(raw, _template):
            counted[point.kind] = counted.get(point.kind, 0) + 1
    if not counted:
        return []
    _passive, active = _by_class()
    if active:
        # F5: the moment Plan 6 registers its first active check, "None were
        # probed" is a sentence this module cannot support. It does not
        # become "all were probed" either -- `check_run.insertion_name`
        # exists but this build's coverage query does not read it, and
        # `requests_sent` is deferred -- so the honest replacement says what
        # is known (active checks ship) and what is not (which points they
        # reached), rather than either claim.
        probed = (f"**{len(active)} active check(s) ship in this build** "
                  f"({_names(active)}), so a point below may have been "
                  "probed. This build records no per-insertion probe "
                  "attribution, so this table cannot say which were and "
                  "which were not.")
    else:
        probed = "**None were probed** — this build ships no active checks."
    out = ["### Insertion points\n",
           "Places a payload could go, derived from the traffic captured. "
           f"{probed}\n",
           "| Kind | Found |", "|---|---|"]
    for kind, n in sorted(counted.items()):
        out.append(f"| `{_cell(kind)}` | {n} |")
    out.append("")
    return out


def _limits(conn, engagement_id) -> list[str]:
    out = ["## Limits\n",
           "What this assessment did not cover, stated rather than implied.\n"]
    out.append("- **No blind-only checks.** This build ships no out-of-band "
               "collector, so vulnerabilities detectable only by an external "
               "interaction were not tested for.")
    out.append("- **No automated crawl.** Attack surface here is what was "
               "browsed through the proxy; anything never visited was never "
               "tested.")
    # F7: this used to read `config.safety_profile` -- TODAY's config, not
    # the profile any run in the store actually ran under -- and only
    # showed the bullet for `production`. Both halves were wrong.
    # `Policy.java` (`DEFAULT_METHODS`, comment at :162-171): the
    # GET/HEAD/OPTIONS allowlist applies whenever `method.allow` is ABSENT
    # from the config body, "whatever profile the configure frame named --
    # the profile is a header field that never reaches this class." Python's
    # `Config` has no `method.allow` field at all, so that allowlist is not
    # conditional on the profile in the first place: it holds for every
    # engagement this CLI can build, staging included. The bullet is
    # therefore unconditional, like its two neighbours above -- a build
    # fact, not a per-run one.
    # F5 (fix round B): the two bullets below used to hardcode "this build
    # ships no active checks" and "Every check in this build is passive".
    # Both were true of this build and neither was derived from it, so Plan
    # 6's first active check makes a client deliverable say something false
    # with nothing to redden. The method-allowlist half of the first bullet
    # is NOT conditional on the corpus and does not move: `Policy.java`'s
    # GET/HEAD/OPTIONS default applies whenever `method.allow` is absent from
    # the config body, and Python's `Config` has no such field, so no check
    # this build can register -- active or not -- can put a payload in a
    # request BODY. What an active check does change is "no request carrying
    # a payload was ever issued", which is about payloads anywhere.
    passive, active = _by_class()
    if active:
        out.append("- **Request-body parameters were recorded but not "
                   f"probed.** This build ships {len(active)} active "
                   f"check(s) ({_names(active)}), and none of them can reach "
                   "a request body: this side of the config has no "
                   "`method.allow` key, so the extension's default method "
                   "allowlist (GET, HEAD, OPTIONS) applies unconditionally, "
                   "whatever safety profile a run named.")
    else:
        out.append("- **Request-body parameters were recorded but not "
                   "probed.** This build ships no active checks, so no "
                   "request carrying a payload was ever issued. Even a "
                   "future active check would be limited the same way "
                   "regardless of a run's safety profile: this side of the "
                   "config has no `method.allow` key, so the extension's "
                   "default method allowlist (GET, HEAD, OPTIONS) applies "
                   "unconditionally.")
    if passive and not active:
        out.append("- **A fixed issue cannot be shown as fixed by "
                   "re-browsing.** "
                   "Every check in this build is passive: it reads this "
                   "engagement's whole captured history for a surface, not "
                   "only the newest traffic. One recorded response is "
                   "therefore enough to keep a finding live for the life of "
                   "the engagement, however much clean traffic follows it. "
                   "Re-running a scan after a fix will still report the "
                   "finding. A retest must be run as a NEW engagement "
                   "against the fixed application; this one is a record of "
                   "what was served during the assessment window.")
    elif passive:
        # A mixed corpus: the disclosure still holds for every finding a
        # PASSIVE check raised, and is false of the rest. Naming which
        # checks it covers is what keeps it a disclosure rather than a
        # blanket that has quietly stopped being true.
        out.append("- **A fixed issue may not be shown as fixed by "
                   "re-browsing.** The passive checks in this build "
                   f"({_names(passive)}) read this engagement's whole "
                   "captured history for a surface, not only the newest "
                   "traffic, so one recorded response keeps a finding of "
                   "theirs live for the life of the engagement however much "
                   "clean traffic follows it; a retest of one must be run as "
                   "a NEW engagement against the fixed application. The "
                   f"active checks ({_names(active)}) re-issue requests and "
                   "are not limited this way.")

    dropped = conn.execute(
        "SELECT COALESCE(SUM(dropped_total), 0) FROM run WHERE engagement_id=?",
        (engagement_id,)).fetchone()[0]
    if dropped:
        out.append(f"- **{dropped} record(s) were dropped during capture.** "
                   "Every count in this report is therefore a **floor**, not "
                   "a total: the assessment saw at least this much, and may "
                   "have seen less than the application offered.")
    out.append("")
    return out
