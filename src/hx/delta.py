"""What changed between a response and its surface's exemplar.

SPEC SECTION 8 PUTS THIS IN THE DIGEST AND GIVES THE REASON: "a bare
{exchange_id, status, bytes, ms} is uninformative: twelve XSS payload variants
against one endpoint return twelve identical-looking tuples". Principle 1 says
handles and digests, never payloads -- and a digest that cannot tell two
responses apart makes Principle 1 a rule against usefulness rather than
against volume.

THE BASELINE IS THE SURFACE'S EXEMPLAR, and there is no other honest choice
available here. `surface.exemplar_exchange_id` is the request that first
defined the endpoint; it is what "normal" means for that surface in this
engagement's own data. A request that reaches no known surface has NO baseline
and the digest then carries `delta_vs_baseline: null` -- not a zero delta,
which would read as "nothing changed" about a comparison never made.

`new_tokens` IS THREE-VALUED FOR THE SAME REASON. `[]` is "computed, none
found"; `null` is "not computed, the bodies were too large to diff". Section
12's rule is that a report which cannot distinguish tested-clean from
never-reached is worse than no report, and a field that spells both `[]` is
that rule broken inside one key.

`baseline_for` RETURNS THE EXEMPLAR'S BODY, NEVER ITS WHOLE STORED RESPONSE.
A review of Task 1's `hx.issue` established why: two responses with
byte-identical content still differ in their `Date:` header and their
per-session `Set-Cookie`, so a delta computed over whole responses counts
that header churn as change -- `new_tokens` fills with `Date`, `ETag` and
cookie-value tokens that have nothing to do with the request under test,
drowning the one signal section 8 built the digest for and potentially
pushing the real reflected payload past `MAX_TOKENS` before it is ever
reported.
"""
from __future__ import annotations

import re

from . import http_text

#: A token is a run of characters a payload or an identifier is made of. The
#: SIX-CHARACTER FLOOR is what makes the field readable: without it every
#: `<div>`, `class`, `href` and `span` in a re-rendered page is a new token,
#: and the one field an agent reads for signal becomes the one it learns to
#: skip. Six admits every realistic payload marker and excludes almost all
#: HTML and English.
TOKEN = re.compile(rb"[A-Za-z0-9_-]{6,}")

#: Reported, never silent -- see `new_tokens_truncated`. A response that
#: differs in three hundred tokens has been rewritten, and the first twenty
#: say so as well as all three hundred would.
MAX_TOKENS = 20

#: Above this, tokens are not computed and the field says so. Two 8 MB bodies
#: tokenised into sets is tens of megabytes of transient allocation inside the
#: one long-lived process that also holds the Burp bridge connection.
MAX_DIFF_BYTES = 2 * 1024 * 1024


def against(baseline_status, baseline_body: bytes,
            status, body: bytes) -> dict:
    """The delta, with `new_tokens` None when the bodies were too big to diff.

    `status_changed` and `len_delta` are ALWAYS computed: they cost nothing
    and they are the two facts that survive a body no one could diff.
    """
    out = {
        "status_changed": baseline_status != status,
        "len_delta": len(body) - len(baseline_body),
        "new_tokens": None,
    }
    if len(body) > MAX_DIFF_BYTES or len(baseline_body) > MAX_DIFF_BYTES:
        return out
    seen = set(TOKEN.findall(baseline_body))
    fresh = []
    for tok in TOKEN.findall(body):
        if tok in seen:
            continue
        seen.add(tok)
        fresh.append(tok.decode("latin-1"))
    if len(fresh) > MAX_TOKENS:
        out["new_tokens_truncated"] = True
        fresh = fresh[:MAX_TOKENS]
    out["new_tokens"] = fresh
    return out


def baseline_for(conn, blobs, surface_id):
    """`(status, body_bytes)` for a surface's exemplar, or None.

    None for every way there is not one: no surface row, no exemplar, an
    exemplar whose response was never stored. All three are "there is nothing
    to compare against", and a caller that told them apart would be reporting
    on its own bookkeeping rather than on the application.

    BODY, NOT THE WHOLE STORED RESPONSE -- see this module's docstring. A
    delta over whole responses counts header churn as change: `new_tokens`
    fills with `Date` and `Set-Cookie` noise, which is the signal section 8
    built the digest for being drowned out by the transport that carried it,
    not by the application.
    """
    row = conn.execute(
        "SELECT x.status, x.resp_blob, x.resp_len FROM surface s"
        " JOIN exchange x ON x.id = s.exemplar_exchange_id"
        " WHERE s.id = ?", (surface_id,)).fetchone()
    if row is None or row[1] is None:
        return None
    _head, body = http_text.split_head_body(blobs.get(row[1], row[2]))
    return row[0], body
