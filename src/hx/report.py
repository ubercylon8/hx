"""One Markdown file: the deliverable.

S12 is specific and this module does exactly what it says and no more -- one
file, in the structure already delivered by hand, not a format x audience
matrix.

THE COVERAGE SECTION IS THE POINT. Findings are what a client reads first and
what any tool can produce. What makes a report honest is the part that says
which checks ran against which surfaces with which verdicts, because that is
what lets someone answer "did you test the password reset flow?" -- and what
makes a retest mean something. S12: a report that cannot distinguish "tested,
clean" from "never reached" is worse than no report.

REDACTION RUNS ON EXPORT. The blobs were redacted at capture and the URL
column was not necessarily; this is the one artifact that leaves the machine,
so `records.redact_url` runs over everything rendered.
"""
from __future__ import annotations

from hx import insertion as insertion_mod
from hx.store import records

_ORDER = ("Critical", "High", "Medium", "Low", "Info")

# The chain grows one row per genuine observation, across every run that ever
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


def render(conn, *, engagement_id, config, blobs=None) -> str:
    out: list[str] = []
    eng = conn.execute(
        "SELECT id, name, client, created_us FROM engagement WHERE id=?",
        (engagement_id,)).fetchone()

    out.append(f"# {eng[2]} — web application assessment\n")
    out.append(f"Engagement `{eng[1]}`.\n")

    out.append("## Scope\n")
    for pattern in config.scope_include:
        out.append(f"- `{pattern}`")
    for pattern in config.scope_exclude:
        out.append(f"- excluded: `{pattern}`")
    out.append("")

    out.extend(_findings(conn, engagement_id))
    out.extend(_coverage(conn, engagement_id))
    if blobs is not None:
        out.extend(_insertion_coverage(conn, engagement_id, blobs))
    out.extend(_limits(conn, engagement_id, config))
    return "\n".join(out) + "\n"


def _findings(conn, engagement_id) -> list[str]:
    rows = conn.execute(
        "SELECT id, title, severity, confidence, description, impact,"
        " remediation, cwe, status FROM finding WHERE engagement_id=?",
        (engagement_id,)).fetchall()
    if not rows:
        return ["## Findings\n", "None recorded.\n"]

    out = ["## Findings\n"]
    by_sev = {s: [r for r in rows if r[2] == s] for s in _ORDER}
    for severity in _ORDER:
        if not by_sev[severity]:
            continue
        out.append(f"## {severity}\n")
        for r in by_sev[severity]:
            fid, title, _sev, confidence, desc, impact, fix, cwe, status = r
            out.append(f"### {title}\n")
            out.append(f"*Confidence: {confidence}*"
                       + (f" · *{cwe}*" if cwe else "")
                       + (f" · *status: {status}*" if status != "new" else "")
                       + "\n")
            for label, text in (("", desc), ("**Impact.** ", impact),
                                ("**Remediation.** ", fix)):
                if text:
                    out.append(f"{label}{text}\n")
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
    shown = rows[:_EVIDENCE_LIMIT]
    for _seq, method, url, status in shown:
        if url is None:
            continue
        out.append(f"- `{method} {records.redact_url(url)}` → {status}")
    omitted = len(rows) - len(shown)
    if omitted > 0:
        # STATED, not silent -- see `_EVIDENCE_LIMIT`. The rows themselves
        # are untouched in the store; only the render is capped.
        out.append(
            f"- … {omitted} further observation(s) omitted (this chain is "
            f"capped at the first {_EVIDENCE_LIMIT} of {len(rows)}; every "
            f"occurrence is still recorded in the store)."
        )
    out.append("")
    return out


def _coverage(conn, engagement_id) -> list[str]:
    rows = conn.execute(
        "SELECT cr.check_id, cr.verdict, COUNT(*), cr.reason FROM check_run cr"
        " JOIN run r ON r.id = cr.run_id WHERE r.engagement_id=?"
        " GROUP BY cr.check_id, cr.verdict, cr.reason"
        " ORDER BY cr.check_id, cr.verdict", (engagement_id,)).fetchall()
    out = ["## Coverage\n"]
    if not rows:
        out.append("This engagement has **not been scanned**. No check has run "
                   "against any surface, so nothing below should be read as "
                   "tested.\n")
        return out

    out.append("Which checks ran against how many surfaces, and what they "
               "answered. A surface absent from this table was **never "
               "reached** — which is not the same as clean.\n")
    out.append("| Check | Verdict | Surfaces | Reason |")
    out.append("|---|---|---|---|")
    for check_id, verdict, n, reason in rows:
        out.append(f"| `{check_id}` | {verdict} | {n} | {reason or ''} |")
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
        except Exception:
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
        out.append(f"| `{kind}` | {n} |")
    out.append("")
    return out


def _limits(conn, engagement_id, config) -> list[str]:
    out = ["## Limits\n",
           "What this assessment did not cover, stated rather than implied.\n"]
    out.append("- **No blind-only checks.** This build ships no out-of-band "
               "collector, so vulnerabilities detectable only by an external "
               "interaction were not tested for.")
    out.append("- **No automated crawl.** Attack surface here is what was "
               "browsed through the proxy; anything never visited was never "
               "tested.")
    if config.safety_profile == "production":
        out.append("- **Request-body parameters were recorded but not "
                   "probed.** The production safety profile permits only "
                   "GET, HEAD and OPTIONS, so no payload reached a request "
                   "body.")

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
