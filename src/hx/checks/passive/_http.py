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
        tuple((row, raw.partition(b"\r\n\r\n")[2]) for row, raw in got.entries),
        got.gaps)


def responses(ctx, exchanges) -> Evidence:
    """`(row, head_bytes)` per readable exchange, plus what could not be read."""
    got = _fetch(ctx, exchanges)
    return Evidence(
        tuple((row, raw.partition(b"\r\n\r\n")[0]) for row, raw in got.entries),
        got.gaps)


def verdict(evidence: Evidence, candidates) -> base.Verdict:
    """The corpus's one rule for when `clean` may be said.

    A check may answer `clean` only when EVERY exchange the surface holds was
    read whole. Anything else -- an exchange whose `outcome` is not `ok`, one
    that stored no response, one whose blob the store cannot hand back -- is
    a gap, and a gap with nothing found is `inconclusive`, never `clean`.

    A CANDIDATE STILL WINS OVER A GAP. What was found was found; incomplete
    coverage does not un-find it, and downgrading a real finding to "could
    not test" would lose the one thing the surface did prove. (What that
    leaves open: `Verdict.finding` carries no reason, so a partially-covered
    surface that DID find something records no trace of the gap. Closing that
    means a reason on a finding verdict, which is a schema-visible change to
    `check_run` semantics and not this fix's.)
    """
    if candidates:
        return base.Verdict.finding(*candidates)
    if not evidence.entries:
        return base.Verdict.inconclusive(
            "no response could be read for this surface" + _detail(evidence))
    if evidence.gaps:
        return base.Verdict.inconclusive(
            "this surface's evidence is incomplete, so nothing found here "
            "separates `tested, clean` from `never reached`" + _detail(evidence))
    return base.Verdict.clean()


def _detail(evidence: Evidence) -> str:
    if not evidence.gaps:
        return ""
    shown = list(evidence.gaps[:_GAPS_SHOWN])
    hidden = len(evidence.gaps) - len(shown)
    if hidden > 0:
        shown.append(f"and {hidden} more")
    return ": " + "; ".join(shown)


def header_names(head: bytes) -> list[str]:
    return [line.partition(b":")[0].decode("latin-1").strip()
            for line in head.split(b"\r\n")[1:] if b":" in line]


def header_values(head: bytes, name: str) -> list[str]:
    """Every value for one header name, ASCII-case-insensitively.

    A list, not a value: `Set-Cookie` legitimately repeats, and a parser that
    returned the first would check one cookie of five and report the surface
    clean.
    """
    want = name.lower()
    out = []
    for line in head.split(b"\r\n")[1:]:
        key, sep, value = line.partition(b":")
        if sep and key.decode("latin-1").strip().lower() == want:
            out.append(value.decode("latin-1").strip())
    return out
