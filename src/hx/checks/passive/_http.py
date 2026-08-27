"""Response parsing shared by the passive corpus.

ONE PARSER, not four. Four checks each splitting heads their own way is four
places for the same off-by-one, and the project has already spent a fix round
on a second implementation of a contract diverging from the first.

`None` from any of these means COULD NOT READ -- a missing blob, a truncated
capture -- and every caller turns that into `inconclusive(reason)`, never
`clean`.
"""
from __future__ import annotations


def _fetch(ctx, exchanges):
    out = []
    for row in exchanges:
        if not row.resp_blob:
            continue
        try:
            out.append((row, ctx.blobs.get(row.resp_blob)))
        except Exception:
            # A blob the store cannot hand back is a record hx has lost. The
            # caller says `inconclusive`; it must not say `clean`.
            continue
    return out or None


def bodies(ctx, exchanges):
    """`(row, body_bytes)` per readable exchange, or None if none were."""
    fetched = _fetch(ctx, exchanges)
    if fetched is None:
        return None
    return [(row, raw.partition(b"\r\n\r\n")[2]) for row, raw in fetched]


def responses(ctx, exchanges):
    """`(row, head_bytes)` per readable exchange, or None if none were."""
    fetched = _fetch(ctx, exchanges)
    if fetched is None:
        return None
    return [(row, raw.partition(b"\r\n\r\n")[0]) for row, raw in fetched]


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
