"""URL to attack surface: the template, not the concrete address.

S5: "Identity is the TEMPLATE, not the concrete URL. /order/1..9999 is one
surface." Everything here serves that sentence.

The two failure directions are not symmetric, and neither is recoverable.
Over-templating MERGES distinct endpoints, and a merged surface is one the
checks visit once and the report covers as though it had visited both.
Under-templating EXPLODES the count, and a surface table with 9,999 rows for
one endpoint makes every coverage number meaningless. `normaliser_version`
records which rules produced a row, but it cannot re-derive the URL, so a
wrong rule is a permanent hole in the evidence rather than a re-runnable step.

So the rules below are deliberately conservative: a segment is templated only
when its SHAPE says identifier, never merely because it is unfamiliar.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

# Bump this when any rule below changes. A rule change without a bump silently
# reinterprets history: rows written yesterday claim a template today's rules
# would never produce, and nothing can tell the two apart afterwards.
NORMALISER_VERSION = 1

_DIGITS = re.compile(r"\A[0-9]+\Z")
_UUID = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z", re.I)
# 32 rather than something shorter because `deadbeef` and `face` are hex AND
# English. Below this length the false-merge risk outweighs the explosion risk.
_HEX = re.compile(r"\A[0-9a-f]{32,}\Z", re.I)
_HAS_DIGIT = re.compile(r"[0-9]")

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_DEFAULT_PORT = {"http": 80, "https": 443}


@dataclass(frozen=True)
class Normalised:
    method: str
    scheme: str
    host: str
    port: int
    path_template: str
    query_key_set: str
    kind: str
    normaliser_version: int


def _decode_segment(seg: str) -> str:
    """Percent-decode one segment, but never into a separator.

    `/order/%31` and `/order/1` are one endpoint and must template alike.
    `/a%2fb` is NOT `/a/b`: whether the server splits on an encoded slash is
    the server's business, and assuming it does would merge two different
    endpoints into one surface. So a decode that would introduce a `/` is
    refused and the segment stays verbatim.

    A malformed escape is left alone for the same reason -- `unquote` is happy
    to hand back `%zz` unchanged, and guessing at a repair would be inventing
    a URL the client never saw.
    """
    decoded = unquote(seg)
    if "/" in decoded:
        return seg
    return decoded


def _template_segment(seg: str, preserve: frozenset[str],
                      slug_threshold: int) -> str:
    if seg in preserve:
        # Checked BEFORE decoding and before every shape rule: `v1` is
        # digit-adjacent and `v2` would otherwise survive only by accident.
        return seg
    decoded = _decode_segment(seg)
    if _DIGITS.match(decoded):
        return "{id}"
    if _UUID.match(decoded):
        return "{uuid}"
    if _HEX.match(decoded):
        return "{hex}"
    # A long segment carrying a digit is a slug: `hello-world-2026-edition`.
    # The digit requirement is what separates this from "anything long" --
    # `/documentation-index` is a route, not an identifier.
    if len(decoded) >= slug_threshold and _HAS_DIGIT.search(decoded):
        return "{slug}"
    return decoded


def path_template(path: str, *, preserve: frozenset[str],
                  slug_threshold: int) -> str:
    """The path with identifier-shaped segments replaced by placeholders."""
    if not path:
        return "/"
    # A trailing slash is significant: `/order/` and `/order` can be different
    # routes, and merging them is a guess about someone else's router. Split
    # keeps the empty final segment, and join puts it back.
    segments = path.split("/")
    out = [segments[0]]   # always "" for an absolute path
    for seg in segments[1:]:
        out.append(_template_segment(seg, preserve, slug_threshold) if seg else seg)
    return "/".join(out)


def query_key_set(query: str) -> str:
    """The comma-joined sorted set of query KEYS, values discarded.

    Two requests to the same endpoint differing only in a value are one
    surface. Two differing in which PARAMETERS they carry are not: a parameter
    is an input, and an input is where a flaw lives.
    """
    if not query:
        return ""
    keys = {k for k, _ in parse_qsl(query, keep_blank_values=True)}
    return ",".join(sorted(keys))


def kind_for(method: str) -> str:
    """Idempotent read, state changing, or unknown -- and unknown is not safe.

    Case-sensitive, per RFC 9110 s9.1. `get` is not GET, and letting a
    lowercase verb inherit `idempotent_read` would hand a check permission to
    replay something the server may treat as a write.
    """
    if method in _SAFE_METHODS:
        return "idempotent_read"
    if method in _STATE_CHANGING:
        return "state_changing"
    return "unknown"


def normalise(method: str, url: str, *, preserve: frozenset[str],
              slug_threshold: int) -> Normalised:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    # Hosts are case-insensitive (RFC 9110 s4.2.3); paths are not. Lowercasing
    # a path would merge /Admin and /admin, which on some servers are two
    # different places and on others are one -- and we do not get to decide
    # which server we are talking to.
    host = (parts.hostname or "").lower()
    port = parts.port or _DEFAULT_PORT.get(scheme, 0)
    return Normalised(
        method=method,
        scheme=scheme,
        host=host,
        port=port,
        path_template=path_template(parts.path, preserve=preserve,
                                    slug_threshold=slug_threshold),
        query_key_set=query_key_set(parts.query),
        kind=kind_for(method),
        normaliser_version=NORMALISER_VERSION,
    )
