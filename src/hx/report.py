"""One Markdown file: the deliverable.

S12 is specific and this module does exactly what it says and no more -- one
file, in the structure already delivered by hand, not a format x audience
matrix.

THE COVERAGE SECTION IS THE POINT. Findings are what a client reads first and
what any tool can produce. What makes a report honest is the part that says
which checks ran with which verdicts, and (via `_coverage`'s `Surfaces`
column) how many distinct surfaces each answer covers -- because that is what
lets someone answer "did you test the password reset flow?" -- and what makes
a retest mean something. S12: a report that cannot distinguish "tested,
clean" from "never reached" is worse than no report.

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


def _redact(text) -> str | None:
    """The one choke point every rendered string that might carry a URL
    passes through. `None` in, `None` out -- callers still decide whether an
    absent field is worth a line."""
    if text is None:
        return None
    return records.redact_url(str(text))


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
    return (str(value).replace("\\", "\\\\").replace("|", "\\|")
           .replace("\r\n", " ").replace("\n", " ").replace("\r", " "))


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

    out.append("## Scope\n")
    for pattern in config.scope_include:
        out.append(f"- `{_redact(pattern)}`")
    for pattern in config.scope_exclude:
        out.append(f"- excluded: `{_redact(pattern)}`")
    out.append("")

    # ONE SOURCE OF TRUTH FOR "HAS THIS ENGAGEMENT EVER BEEN SCANNED",
    # shared by `_findings` (F4 of fix round 1: an unscanned engagement's
    # "None recorded" must not read as a clean bill) and `_coverage` (the
    # original "not been scanned" paragraph). Computed once here rather than
    # twice, differently, in two functions that would otherwise be free to
    # quietly disagree.
    scanned = bool(conn.execute(
        "SELECT 1 FROM check_run cr JOIN run r ON r.id = cr.run_id"
        " WHERE r.engagement_id=? LIMIT 1", (engagement_id,)).fetchone())

    out.extend(_findings(conn, engagement_id, scanned=scanned))
    out.extend(_coverage(conn, engagement_id, config, scanned=scanned))
    if blobs is not None:
        out.extend(_insertion_coverage(conn, engagement_id, blobs))
    out.extend(_limits(conn, engagement_id))
    return "\n".join(out) + "\n"


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


def _findings(conn, engagement_id, *, scanned) -> list[str]:
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
        return ["## Findings\n", "None recorded.\n"]

    out = ["## Findings\n"]
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


def _coverage(conn, engagement_id, config, *, scanned) -> list[str]:
    out = ["## Coverage\n"]
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
            "SELECT cr.check_id, cr.verdict, COUNT(DISTINCT cr.surface_id),"
            " cr.reason FROM check_run cr"
            " JOIN run r ON r.id = cr.run_id WHERE r.engagement_id=?"
            " GROUP BY cr.check_id, cr.verdict, cr.reason"
            " ORDER BY cr.check_id, cr.verdict", (engagement_id,)).fetchall()

        out.append("Which checks ran against how many distinct surfaces, "
                   "and what they answered. A surface absent from this "
                   "table was **never reached** — which is not the same "
                   "as clean.\n")
        out.append("| Check | Verdict | Surfaces | Reason |")
        out.append("|---|---|---|---|")
        for check_id, verdict, n, reason in rows:
            out.append(f"| `{_cell(check_id)}` | {_cell(verdict)} | {n} |"
                       f" {_cell(_redact(reason))} |")
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
    return out


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
    out = ["### Insertion points\n",
           "Places a payload could go, derived from the traffic captured. "
           "**None were probed** — this build ships no active checks.\n",
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
    out.append("- **Request-body parameters were recorded but not "
               "probed.** This build ships no active checks, so no request "
               "carrying a payload was ever issued. Even a future active "
               "check would be limited the same way regardless of a run's "
               "safety profile: this side of the config has no "
               "`method.allow` key, so the extension's default method "
               "allowlist (GET, HEAD, OPTIONS) applies unconditionally.")
    out.append("- **A fixed issue cannot be shown as fixed by re-browsing.** "
               "Every check in this build is passive: it reads this "
               "engagement's whole captured history for a surface, not only "
               "the newest traffic. One recorded response is therefore enough "
               "to keep a finding live for the life of the engagement, "
               "however much clean traffic follows it. Re-running a scan "
               "after a fix will still report the finding. A retest must be "
               "run as a NEW engagement against the fixed application; this "
               "one is a record of what was served during the assessment "
               "window.")

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
