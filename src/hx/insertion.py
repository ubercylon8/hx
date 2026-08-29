"""Insertion points, derived from one captured request.

S5 is explicit that these are DERIVED, NOT STORED -- there is no `insertion`
table in v1. `insertion_name` lives as a column on `check_run`; `finding`
carries both `insertion_name` and `insertion_kind` -- checked against
schema.sql, 2026-08-27 -- each column existing only where that table needs it
for identity.

THE DERIVATION SOURCE. The master spec calls it `surface.detail`. THERE IS NO
SUCH COLUMN -- grepped, 2026-08-27 -- so the real path is
`surface.exemplar_exchange_id` -> that exchange's `req_blob` -> these bytes.
Naming it here rather than inheriting a reference to something that does not
exist is the point of this paragraph.

PURE, AND THAT IS DELIBERATE: bytes in, insertion points out. No database, no
blob store, no Burp. The runner does the fetching; this decides what is in
there.

WHAT IS NOT AN INSERTION POINT, and why each exclusion is a decision rather
than an oversight:

  * `Host` -- changing it changes which server answers, which is a scope
    question and not a payload;
  * `Content-Length` and `Content-Type` -- structural; a payload there breaks
    the request rather than testing the application;
  * `Cookie` as a single header -- individual cookies are derived instead, and
    deriving both would double the coverage denominator for one input. This
    exclusion is NOT carried by `_NOT_INSERTABLE`: the loop below branches on
    `low == "cookie"` and `continue`s unconditionally after expanding the
    crumbs, so `Cookie` never reaches the `_NOT_INSERTABLE` check at all.
    Putting `"cookie"` in the set as well would be a second, dead guard --
    removing it changes nothing, which is precisely the shape Rule 2 forbids
    -- so it is not there;
  * `Connection`, `Transfer-Encoding`, `Upgrade`, `Expect`, `Accept-Encoding`
    -- hop-by-hop or transport-negotiation headers (RFC 9110 SS7.6.1 plus
    `Expect`): a proxy or the target server, not the application, acts on
    these, so a payload there tests the transport rather than the app.
    `test_headers_are_derived_but_hop_by_hop_and_fixed_ones_are_not` names
    all eight `_NOT_INSERTABLE` members explicitly (`Cookie` is asserted too,
    but exercises the branch above, not this set) -- Rule 2: a guard only
    counts as tested by the input that separates it from its absence, and an
    exclusion no test names is indistinguishable from one that was never
    there.

The body kinds ARE derived and are NOT probeable in this plan or Plan 6: S4's
production method allowlist is GET/HEAD/OPTIONS, so an active_safe check can
only re-issue a GET. They are recorded so the coverage section can say
`exists, not probed`, which is worth more than omitting them.
"""
from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlsplit

from hx.checks.base import Insertion

# Headers that are structural, hop-by-hop, or derived more usefully another
# way. Lower-cased for an ASCII-insensitive match, the way the redactor does.
# `Cookie` is NOT here -- see the module docstring -- because the cookie
# branch below already `continue`s before this set is ever consulted, and a
# second guard removing it would change nothing. Every name that IS here is
# asserted absent by
# test_headers_are_derived_but_hop_by_hop_and_fixed_ones_are_not, with each
# one individually confirmed (by deletion) to redden that test.
_NOT_INSERTABLE = frozenset({
    "host", "content-length", "content-type", "connection",
    "transfer-encoding", "upgrade", "expect", "accept-encoding",
})


def is_placeholder(segment: str) -> bool:
    """Whether one path segment is a template placeholder.

    THE ONE DEFINITION OF THE SHAPE, and it is read from two places rather
    than spelt in each: `derive` below turns a placeholder into a
    `path_segment` insertion point, and `hx.checks.probe.ProbeSender.get`
    REFUSES to put one on the wire. Two spellings of "starts with `{`, ends
    with `}`" would be two chances to disagree about the one thing separating
    a template from an address, and the second of those callers is a safety
    guard.

    `hx.surface._template_segment` is what mints these -- `{id}`, `{uuid}`,
    `{hex}`, `{slug}` -- and `hx.surface._kept_segment` percent-encodes a
    literal `{` or `}` in every segment it KEEPS, so no captured segment can
    forge one. `len > 2` excludes `{}`, which nothing mints.
    """
    return segment.startswith("{") and segment.endswith("}") and len(segment) > 2


def _request_target(head: bytes) -> str | None:
    """The request line's target, or None when there is no readable one.

    The one place a captured request's request line is read. `request_path`
    wants its path, `derive` wants its query, and a second `split` somewhere
    else is a second chance to disagree about which field is which.

    Tolerates a bare LF (RFC 9112 s2.2 requires a recipient to accept one),
    stripping at most one trailing CR the way `hx.checks.passive._http.
    _header_lines` does rather than every trailing CR: a lone CR before the
    terminator is data.
    """
    line = head.split(b"\n", 1)[0]
    if line.endswith(b"\r"):
        line = line[:-1]
    parts = line.split(b" ")
    if len(parts) < 2:
        return None
    return parts[1].decode("latin-1")


def request_path(request_bytes: bytes) -> str | None:
    """The CONCRETE path this request asked for, in origin form.

    THE ADDRESS, NOT THE TEMPLATE. `hx.surface` normalises `/user/12345/
    profile` into the surface row's `path_template` `/user/{id}/profile`,
    which is an identity and not somewhere a request can be sent: every
    active check that built its probe out of it addressed a URL that cannot
    exist and read the 404 as a clean answer. `hx.scan.run` reads this off
    the surface's exemplar request instead and hands it to
    `probe.ProbeSender`, so a probe goes where the capture went.

    `urlsplit` because a captured request line can be ABSOLUTE-form as well
    as origin-form -- that is how a browser addresses a proxy, which is the
    only way anything reaches `hx.capture` today -- and the path is the same
    field either way.

    `None` rather than a guess for a request whose line cannot be read, or
    whose target has no absolute path (`OPTIONS *`, an authority-form
    CONNECT). The caller's answer to that is a `skipped` row naming it, never
    a probe aimed at something invented here.
    """
    target = _request_target(request_bytes)
    if target is None:
        return None
    path = urlsplit(target).path
    return path if path.startswith("/") else None


def derive(request_bytes: bytes, path_template: str) -> tuple[Insertion, ...]:
    """Every place a payload could go in this request.

    Returns a tuple sorted by `(kind, name)`. The ordering is not cosmetic:
    two scans of one surface must produce the same `check_run` rows in the
    same order, or a retest diff fills with noise that is really just
    iteration order.
    """
    head, sep, body = request_bytes.partition(b"\r\n\r\n")
    if not sep:
        # No head terminator: a truncated or malformed capture. Nothing
        # useful can be said about it, and raising would take a whole scan
        # down over one bad row.
        return ()

    lines = head.split(b"\r\n")
    found: set[Insertion] = set()

    # --- the request line: query parameters and templated path segments ---
    target = _request_target(head)
    if target is not None:
        for name, _value in parse_qsl(urlsplit(target).query,
                                      keep_blank_values=True):
            if name:
                found.add(Insertion("query", name))

    # The TEMPLATE is the authority on which segments are variable, because
    # the normaliser already decided that and the finding is attributed to the
    # surface it produced. Re-guessing here would disagree with it.
    for segment in path_template.split("/"):
        if is_placeholder(segment):
            found.add(Insertion("path_segment", segment))

    # --- headers and cookies ---
    content_type = ""
    for raw in lines[1:]:
        name, sep, value = raw.partition(b":")
        if not sep:
            continue
        key = name.decode("latin-1").strip()
        val = value.decode("latin-1").strip()
        low = key.lower()
        if low == "content-type":
            content_type = val.lower()
        if low == "cookie":
            for crumb in val.split(";"):
                cname = crumb.split("=", 1)[0].strip()
                if cname:
                    found.add(Insertion("cookie", cname))
            continue
        if low in _NOT_INSERTABLE or not key:
            continue
        found.add(Insertion("header", key))

    # --- the body ---
    if body:
        if "application/x-www-form-urlencoded" in content_type:
            for name, _value in parse_qsl(body.decode("latin-1"),
                                          keep_blank_values=True):
                if name:
                    found.add(Insertion("body_form", name))
        elif "json" in content_type:
            found.update(_json_members(body))

    return tuple(sorted(found, key=lambda i: (i.kind, i.name)))


def _json_members(body: bytes) -> set[Insertion]:
    """Every scalar-or-array member of a JSON body, by dotted path.

    A malformed body yields nothing rather than raising: the capture is
    whatever the client sent, and a scan must survive an application that
    mislabels its own content type.
    """
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return set()

    out: set[Insertion] = set()

    def walk(node, prefix: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{prefix}.{key}" if prefix else str(key))
        elif prefix:
            # A list is one insertion point, not one per element: probing
            # `items[0]` and `items[1]` separately multiplies the budget by
            # the data's length, which is the application's choice and not a
            # measure of its attack surface.
            out.add(Insertion("body_json", prefix))

    walk(parsed, "")
    return out
