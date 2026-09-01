"""Response parsing shared by the passive corpus.

ONE PARSER, not four. Four checks each splitting heads their own way is four
places for the same off-by-one, and the project has already spent a fix round
on a second implementation of a contract diverging from the first.

`Evidence` CARRIES BOTH HALVES: the responses a check could read, and the
exchanges it could not. Until F6 of the whole-branch review these functions
returned only the first half, plus `None` when NOTHING at all was readable --
so a surface where one exchange of two never answered was scanned as though
it were complete and its silence recorded as `clean`. MEASURED, one readable
fully-headed response beside one `status_unreadable` exchange:
`check_run` said `('clean', NULL)`, byte for byte what a wholly tested,
wholly clean surface says.

Design S5 names this failure in the schema itself -- of `exchange.outcome`:
"a transport failure has no HTTP status; without `outcome` a check reads
silence as 'not vulnerable'". S10 says the answer: "A check that cannot run
returns `inconclusive(reason)` -- never `clean`". And S12 says why it
matters: a report that cannot distinguish "tested, clean" from "never
reached" is worse than no report. `verdict()` below is the one place that
distinction is made, for all four checks.
"""
from __future__ import annotations

from dataclasses import dataclass

from hx.checks import base
from ...http_text import (  # noqa: F401
    # PROMOTED FOR PLAN B. `hx.issue` needs the same parsing one layer down,
    # and a core module importing from `hx.checks.passive` would invert the
    # dependency. Re-exported under the names this module already used, so
    # nothing in `hx/checks/` changes and the behavioural tests that earned
    # these rules stay where they are. `header_names` and `header_values` are
    # re-exports for this module's importers rather than for its own body,
    # hence the noqa.
    header_lines as _header_lines,
    header_names,
    header_values,
    split_head_body as _split_head_body,
)

# The one `exchange.outcome` value meaning a COMPLETE response is on file.
#
# `truncated` and `status_unreadable` did bring bytes back, and those bytes
# are still read for what they contain -- a private key in a partial body is
# a private key -- but neither response is whole, so neither can license
# `clean`: the header that was going to be missing may simply be past the cut.
# Every other value means nothing came back at all; `hx.capture`'s own
# docstring puts it as the row keeping "a NULL [status], and that NULL is the
# reading: nothing on the far side ever answered".
_COMPLETE = "ok"

# How many gaps a reason names before it summarises. A surface can hold
# hundreds of exchanges, and an operator reading a coverage table needs
# enough to recognise the shape of the failure, not a transcript of it.
_GAPS_SHOWN = 3


@dataclass(frozen=True)
class Evidence:
    """What a check could read from a surface, and what it could not.

    `gaps` is one string per exchange whose evidence is missing or partial,
    naming the exchange and why. An exchange can appear in BOTH `entries` and
    `gaps`: a truncated response is worth searching and is not proof of
    absence.
    """
    entries: tuple
    gaps: tuple[str, ...]


def _fetch(ctx, exchanges) -> Evidence:
    entries, gaps = [], []
    for row in exchanges:
        gap = None
        if row.outcome != _COMPLETE:
            gap = f"{row.id}: outcome={row.outcome}"
        elif not row.resp_blob:
            gap = f"{row.id}: no response was stored"
        if row.resp_blob:
            try:
                entries.append((row, ctx.blobs.get(row.resp_blob)))
            except Exception:
                # A blob the store cannot hand back is a record hx has lost.
                # The outcome, where there is one, is the more specific fact
                # and keeps its place.
                gap = gap or f"{row.id}: response blob could not be read"
        if gap is not None:
            gaps.append(gap)
    return Evidence(tuple(entries), tuple(gaps))


def bodies(ctx, exchanges) -> Evidence:
    """`(row, body_bytes)` per readable exchange, plus what could not be read."""
    got = _fetch(ctx, exchanges)
    return Evidence(
        tuple((row, _split_head_body(raw)[1]) for row, raw in got.entries),
        got.gaps)


def responses(ctx, exchanges) -> Evidence:
    """`(row, head_bytes)` per readable exchange, plus what could not be read."""
    got = _fetch(ctx, exchanges)
    return Evidence(
        tuple((row, _split_head_body(raw)[0]) for row, raw in got.entries),
        got.gaps)


def verdict(evidence: Evidence, candidates, *,
            considered: tuple[str, ...] = ()) -> base.Verdict:
    """The corpus's one rule for when `clean` may be said.

    A check may answer `clean` only when EVERY exchange the surface holds was
    read whole. Anything else -- an exchange whose `outcome` is not `ok`, one
    that stored no response, one whose blob the store cannot hand back -- is
    a gap, and a gap with nothing found is `inconclusive`, never `clean`.

    A CANDIDATE STILL WINS OVER A GAP. What was found was found; incomplete
    coverage does not un-find it, and downgrading a real finding to "could
    not test" would lose the one thing the surface did prove. What a gap DOES
    take from a finding is `considered`: the finding is reported, and the
    surface's other issue types are not retired on evidence that was never
    read. (What that leaves open: `Verdict.finding` carries no reason, so a
    partially-covered surface that DID find something records no trace of the
    gap in its own row. Closing that means a reason on a finding verdict,
    which is a schema-visible change to `check_run` semantics and not this
    fix's.)

    `considered` NAMES WHAT THE CHECK EXAMINED, and only the two conclusive
    returns carry it. An `inconclusive` verdict deliberately does not: the
    surface's evidence was incomplete, so the check concluded nothing, and
    `hx.scan._mark_unobserved` must not retire a finding on the strength of a
    response it could not read.
    """
    if candidates:
        # F5 of the whole-branch review. This used to pass `considered`
        # unconditionally while the `clean` return below required zero gaps,
        # and the asymmetry retires findings: `considered` is what
        # `hx.scan._mark_unobserved` reads, so a surface holding one
        # unreadable exchange and one candidate found elsewhere claimed to
        # have EXAMINED every issue type this check names -- including,
        # exactly, the type whose only evidence was the exchange that could
        # not be read. The finding is still reported (a candidate wins over a
        # gap, above); what it may not do is retire its neighbours on
        # evidence nobody could read.
        return base.Verdict.finding(
            *candidates, considered=() if evidence.gaps else considered)
    if not evidence.entries:
        return base.Verdict.inconclusive(
            "no response could be read for this surface"
            + _detail(evidence.gaps))
    if evidence.gaps:
        return base.Verdict.inconclusive(
            "this surface's evidence is incomplete, so nothing found here "
            "separates `tested, clean` from `never reached`"
            + _detail(evidence.gaps))
    return base.Verdict.clean(considered=considered)


def _detail(gaps: tuple[str, ...]) -> str:
    """The gap list as a coverage row shows it -- at most `_GAPS_SHOWN`, then
    a count.

    TAKES THE GAPS AND NOT AN `Evidence`, so that the active corpus can use
    it too: `hx.checks.active._probe_util.verdict` collects a gap per probe
    that came back without answering, and an operator reading a coverage row
    must see them spelt the same way whichever half of the corpus wrote the
    row.
    """
    if not gaps:
        return ""
    shown = list(gaps[:_GAPS_SHOWN])
    hidden = len(gaps) - len(shown)
    if hidden > 0:
        shown.append(f"and {hidden} more")
    return ": " + "; ".join(shown)
