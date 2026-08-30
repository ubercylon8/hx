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

WHERE THIS DIVERGES FROM `Policy` (extension/src/hx/policy/Policy.java), the
gate that decided the request was allowed at all. A difference between them is
a difference between what was AUTHORISED and what is RECORDED, so each one is
named here rather than left to be found in a report:

  - PATH CASE IS KEPT. Policy folds case before matching; merging `/Admin`
    with `/admin` would be a guess about someone else's router.
  - `%2f` DOES NOT SPLIT A SEGMENT. Policy reads a path several ways at once
    and one of them splits; a surface row is a single string and has to pick,
    and picking "the server split on it" merges two endpoints.
  - DECODING DEPTH IS MIRRORED -- see `_decode_segment`. This is the one that
    was a divergence and is now deliberately not one.
  - DECODING CHARSET DIFFERS. `Policy.decodeOnce` maps each escaped byte to
    one char with no transcoding; `unquote` here reads the escaped bytes as
    UTF-8 and leaves the whole segment verbatim when they are not UTF-8. The
    two agree on every ASCII escape, which is every escape a rule below can
    match on. They differ in how many CHARACTERS a non-ASCII segment has,
    which can move it across `slug_threshold`.
  - THE AUTHORITY IS RECORDED, NOT JUDGED. `Target.parse` and
    `checkHostChars` refuse userinfo, a leading or trailing dot, an empty
    label, a non-ASCII host, an IPv6 literal, an empty port and port 0.
    `normalise` refuses none of them: it says what happened, it does not
    decide whether it was allowed to. A request carrying one is `scope_denied`
    at the gate (`Policy.checkScope` turns the parse failure into a denial),
    so it reaches this module only from a caller that did not go through the
    gate.
  - HOST CASE FOLDING DIFFERS IN UNICODE'S CONDITIONAL CASES. Both sides fold
    U+212A KELVIN SIGN to `k`, so that one is not a divergence. `str.lower()`
    is Unicode's FULL mapping and `Policy.lower` is the SIMPLE one, so U+0130
    is two characters here and one there. Only a non-ASCII host can notice,
    and Policy refuses those.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, unquote, urlsplit

# Bump this when any rule below changes. A rule change without a bump silently
# reinterprets history: rows written yesterday claim a template today's rules
# would never produce, and nothing can tell the two apart afterwards.
#
# 1 -> 2 (fix round 1): a kept segment now has `{` and `}` percent-encoded so
# it cannot spell a placeholder; `query_key_set` escapes its own delimiter and
# distinguishes an empty key from no query; `preserve` is matched AFTER
# decoding; decoding runs to a fixed point rather than once; a segment whose
# escapes are not UTF-8 is kept verbatim rather than folded to U+FFFD.
NORMALISER_VERSION = 2

# Mirrors Policy.MAX_DECODE_ROUNDS. See `_decode_segment`; a test reads the
# constant out of Policy.java so the two cannot drift apart in silence.
MAX_DECODE_ROUNDS = 16

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

# What an empty query KEY is written as, so that `?=1` and no query at all are
# not the same row. Any other spelling of "nothing" would be a key some request
# could carry: `_encoded_key` emits only unreserved characters and `%XX`, and
# `(` is neither, so no key can forge this one.
_EMPTY_KEY = "(empty)"


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


def _decode_once(seg: str) -> str:
    """One round of percent-decoding, or the input when it cannot be read.

    `errors="strict"` and not the default `"replace"`: `unquote` folds every
    one of the 128 invalid single-byte escapes to U+FFFD, so `%80` through
    `%FF` would template to the same segment and 128 distinct requests would
    be recorded as one surface. Returning the input unchanged instead is the
    same policy this module already applies to `%zz` -- leave what it cannot
    read alone rather than invent a URL the client never sent -- and it makes
    the round a no-op, which stops the fixed-point loop below.
    """
    try:
        return unquote(seg, errors="strict")
    except UnicodeDecodeError:
        return seg


def _decode_segment(seg: str) -> str:
    """Percent-decode one segment to a fixed point, but never into a separator.

    `/order/%31` and `/order/1` are one endpoint and must template alike.

    TO A FIXED POINT, mirroring `Policy.decodeToFixedPoint`, under the same
    bound: `Policy` matches its rules against a SET of readings of the path,
    and one member of that set is the fully-decoded one, so `/order/%2531` is
    among other things `/order/1` to the gate that authorised it. Decoding
    once here would record it as `/order/%31` -- the row and the thing that
    was authorised naming different endpoints -- and would split it from
    `/order/1` besides.
    The two cannot share code across the language boundary, so the agreement
    is pinned by a test that reads Policy's constant.

    Past the bound the partially decoded string is returned, which is what
    `decodeToFixedPoint` does. Policy turns that case into a DENIAL
    (`decodesFully`), so a request that needs more than sixteen rounds does
    not reach this module through the gate.

    `/a%2fb` is NOT `/a/b`: whether the server splits on an encoded slash is
    the server's business, and assuming it does would merge two different
    endpoints into one surface. So a decode that would introduce a `/` is
    refused and the segment stays verbatim -- and it is refused however deeply
    the slash was nested, because `%252f` decodes to it too.
    """
    decoded = seg
    for _ in range(MAX_DECODE_ROUNDS):
        nxt = _decode_once(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    if "/" in decoded:
        return seg
    return decoded


def _kept_segment(seg: str) -> str:
    """A segment that survives templating, spelt so it cannot BE a template.

    `{` and `}` are this module's placeholder syntax, so a segment allowed to
    carry them literally can spell one: `/order/{id}` and `/order/%7Bid%7D`
    both template to `/order/{id}`, which is the row `/order/1` and
    `/order/9999` share. Task 4's upsert then moves that row's
    `last_seen_run` onto a request that never touched the endpoint, and if the
    forgery is the FIRST sighting it is the row's `exemplar_exchange_id` for
    good -- the exemplar is written on insert and the planned `DO UPDATE SET`
    does not touch it. A page shipping an un-interpolated `href="/order/{id}"`
    is enough.

    Escaping the braces instead of choosing a rarer delimiter is the fix,
    because a rarer delimiter is the same defect with a longer fuse. It is
    injective on a segment that REACHED its fixed point: such a segment holds
    no valid escape, so a `%7B` in the output came from a `{` and from nothing
    else. Two shapes sit outside that: a segment kept verbatim by the `/`
    refusal above, where `a{b%2fc` and `a%7Bb%2fc` both give `a%7Bb%2fc` --
    two spellings of one decoded segment, which is a merge this module makes
    everywhere else and not a merge of two endpoints -- and a segment still
    encoded past the round bound, which `Policy` answers with a denial.
    """
    return seg.replace("{", "%7B").replace("}", "%7D")


# EVERY STRING `_template_segment` CAN MINT, and nothing else in this module
# may return one that is not here. It is a vocabulary two other modules
# reason about -- `hx.insertion.is_placeholder` decides the SHAPE, which is
# a different question, and `hx.checks.active.path_traversal` asks whether
# its own name filter can ever match one of these (it cannot: none of them
# looks like a filename, so that check can never probe a templated segment,
# which `hx.report._limits` discloses). Pinned against the normaliser's real
# output by `tests/test_surface.py`, in both directions: nothing outside this
# tuple is minted, and every entry in it is reachable.
PLACEHOLDERS = ("{id}", "{uuid}", "{hex}", "{slug}")


def _template_segment(seg: str, preserve: frozenset[str],
                      slug_threshold: int) -> str:
    decoded = _decode_segment(seg)
    if decoded in preserve:
        # Checked AFTER decoding, and that ordering is the point: with
        # `preserve={"2024"}`, `/%32024/report` is the same request to the same
        # server as `/2024/report`, and matching the raw spelling let one
        # escape defeat the operator's explicit "this segment is a route" AND
        # merge the encoded spelling into the numeric-id family.
        return _kept_segment(decoded)
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
    return _kept_segment(decoded)


def path_template(path: str, *, preserve: frozenset[str],
                  slug_threshold: int) -> str:
    """The path with identifier-shaped segments replaced by placeholders."""
    if not path:
        return "/"
    # A trailing slash is significant: `/order/` and `/order` can be different
    # routes, and merging them is a guess about someone else's router. Split
    # keeps the empty final segment, and join puts it back. An empty segment
    # needs no special case here: `_template_segment("")` is `""` under every
    # configuration -- no shape rule matches the empty string, and the one
    # rule that can (`preserve={""}`) returns it unchanged.
    segments = path.split("/")
    out = [segments[0]]   # always "" for an absolute path
    for seg in segments[1:]:
        out.append(_template_segment(seg, preserve, slug_threshold))
    return "/".join(out)


def _encoded_key(key: str) -> str:
    """One query key, spelt so that the join below cannot be misread.

    `,` separates keys, so a key containing one has to be escaped or the field
    lies about how many inputs the request carried: `a%2Cb=1` is ONE parameter
    and `a=1&b=2` is two, and both used to render `a,b`. A parameter is an
    input and an input is where a flaw lives, so a check reading this field
    would enumerate the wrong ones. `quote(safe="")` escapes `%` as well as
    `,`, without which `a%2Cb` (the literal key) and `a,b` would collide in
    turn.
    """
    return quote(key, safe="") if key else _EMPTY_KEY


def query_key_set(query: str) -> str:
    """The comma-joined sorted set of query KEYS, values discarded.

    Two requests to the same endpoint differing only in a value are one
    surface. Two differing in which PARAMETERS they carry are not: a parameter
    is an input, and an input is where a flaw lives.

    No query at all is `""`. A query carrying the empty key -- `?=1` -- is
    `(empty)`, because `GET /x` and `GET /x?=1` are not the same request and a
    field that renders both as `""` merges them.
    """
    keys = {k for k, _ in parse_qsl(query, keep_blank_values=True)}
    return ",".join(_encoded_key(k) for k in sorted(keys))


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
    """One request as the surface row it belongs to.

    NOT TOTAL, and the caller owes it a url. `urlsplit` raises `ValueError` on
    an unterminated IPv6 literal (`http://[fe80::/x`), and `parts.port` raises
    on a port that is not a number or is out of range (`http://h:abc/x`,
    `http://h:99999/x`). Nothing here catches those: a url this cannot parse
    is one the enforcement gate has already refused -- `Policy.checkScope`
    turns exactly these into `scope_denied` -- so swallowing the error would
    record a surface for a request that had no authority behind it. A caller
    reaching this module by some other route (a `via='send'` or `via='crawl'`
    string that never went through `Policy.Target.parse`) must be prepared for
    the exception.
    """
    parts = urlsplit(url)
    # `urlsplit` has already lowercased the scheme, and `parts.hostname` the
    # host -- everything up to the first `%`, treating whatever follows as an
    # IPv6 zone id and deliberately leaving its case alone. A second `.lower()`
    # here was dead for every host that does not carry a `%`, which is the
    # only thing it could still change -- `[fe80::1%tESt]` and `EX%41MPLE.test`
    # are what that looks like -- and there it fought that deliberate choice.
    # `Policy` refuses a `%` and a bracket alike (`checkHostChars`), so it
    # asserted a normalisation this function does not perform, on inputs that
    # cannot reach it through the gate.
    scheme = parts.scheme
    # Hosts are case-insensitive (RFC 9110 s4.2.3); paths are not. Lowercasing
    # a path would merge /Admin and /admin, which on some servers are two
    # different places and on others are one -- and we do not get to decide
    # which server we are talking to.
    host = parts.hostname or ""   # None for a url with no authority at all
    # `is not None` and not `or`: port 0 is falsy, and `or` recorded `http://
    # h:0/x` on port 80 -- a row naming an endpoint nobody addressed. 0 is
    # also the port an unknown scheme gets, and scheme is in the UNIQUE key,
    # so the two cannot collide.
    port = parts.port if parts.port is not None else _DEFAULT_PORT.get(scheme, 0)
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
