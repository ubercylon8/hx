"""Reflected input -- a canary per insertion point, and nothing claimed
beyond what came back.

WHAT THIS CHECK PROVES AND WHAT IT DOES NOT. `active_safe` (S10) means
idempotent GET/HEAD only: this check plants a value and reads the response,
and it never renders what comes back, never executes it, and never chains a
second request off anything a response named (the same discipline
`open_redirect.py` documents for `Location`). That means the strongest true
sentence available to it is "this input came back in the response" -- NOT
"this is exploitable", which needs a browser, a DOM, and a sink this check
never builds. Every candidate below says the first sentence and is careful
never to say the second; see `_UNESCAPED_TITLE`/`_PLAIN_TITLE` and the
descriptions built around them.

BUDGET: CANARY-FIRST. One request per insertion point, carrying a marker
that cannot occur naturally and cannot itself do anything (`_probe_util.
canary()` -- alphanumeric only, see its own docstring). A surface with N
insertion points and nothing reflecting anywhere costs exactly N requests --
`test_one_request_per_point_until_something_reflects` pins this. Nothing is
skipped by a name heuristic the way `open_redirect.py` skips
non-redirect-shaped parameters: reflection is not restricted to
conventionally-named parameters the way a redirect target is, so every
insertion point of a kind this check declares gets its own probe.

ESCALATION, ONLY WHEN THE FIRST CANARY CAME BACK. A bare alphanumeric marker
proves reflection but says nothing about CONTEXT: a value reflected inside
an HTML comment or a fully-escaped attribute is a much weaker finding than
one reflected where `<`, `>`, `"` and `'` survive intact, because those are
the characters that matter for breaking out of a tag, an attribute, or a
quoted string. So a reflecting point costs a SECOND request -- never more --
that plants a fresh canary wrapped in exactly those four characters
(`_META_CHARS`) and asks the same question `_probe_util.reflected` already
knows how to answer: is this exact string, unescaped, in the response?
Wrapping rather than listing individual characters keeps the escalation to
one request instead of four, at the cost of an all-or-nothing answer -- a
target that escapes `<` but not `'` reads here as "did not survive", which
is the conservative direction: this check would rather understate context
than claim more than the one request it sent can support. THE ESCALATION
PAYLOAD IS NOT `_probe_util.canary()` -- that function's contract is
alphanumeric-only, and an escalation that needs metacharacters builds them
itself, on top of a fresh canary `_probe_util.canary()` still supplies (see
`_probe_util.py`'s own docstring for why that split is where it is). Sending
`<>"'` in a GET parameter is still `active_safe`: nothing here is a script,
nothing here is rendered by anything that could run it, and the request
that carries it is exactly as idempotent as the one before it.

EACH INSERTION POINT GETS ITS OWN CANARY, NEVER A SHARED ONE.
`_probe_util.canary()` mints a fresh value on every call, and this check
calls it once per point (twice, on the second request, for a point that
escalates) rather than once per surface -- see `_probe_util.py`'s own
docstring for why a repeated marker cannot tell two reflecting points apart.
`records.dedupe_key` folds `insertion_kind`/`insertion_name` into a
finding's identity, and, like `open_redirect.py` (unlike `cors.py`, which
has no insertion point to name), every candidate below carries its own
`insertion` so two independently-reflecting points on one surface stay two
rows instead of colliding into one.

CONSIDERED, AND WHY THIS CHECK'S CASE IS THE PLAIN ONE DESPITE THE WARNING.
There is exactly one issue type, `_ISSUE_TYPE`, covering every insertion
kind this check probes -- unlike `security_headers.py`'s per-header table or
`cookie_flags.py`'s per-cookie-name minting, reflection is one question
asked at every point, not a family of questions. `hx.scan.run` never calls
`probes()` with an empty `insertions` tuple for a check whose
`insertion_kinds` is non-empty (a surface with none of the declared kinds is
`skipped` with reason `no_insertion_point`, and one whose declared points are
all ones the send path refuses with `no_probeable_insertion_point`, before
this check is ever reached -- see the `usable`/`wanted` guard in `scan.py`),
so in practice every call this check receives is handed at least one point it
could send to. `probed_any` is
still tracked explicitly, defensively, rather than assumed: a `considered`
that named the issue type on a call that genuinely probed nothing would let
`hx.scan._mark_unobserved` retire a finding on the strength of a question
this check never got to ask, which is the exact mistake the module doc on
`base.Verdict.considered` exists to prevent. A POINT THAT REFLECTED NOTHING
WAS STILL EXAMINED: the one request that carries its canary and reads it
back absent IS the examination, the same way a clean answer from `cors.py`'s
one request means its three issue types were all looked at and none applied
-- "examined" never meant "found something", here or in either predecessor.

THE PROBE GOES TO THE EXEMPLAR'S OWN PATH (`sender.path`), NOT TO THE SURFACE
ROW'S `path_template`, AND THE PATH-SEGMENT SUBSTITUTION IS BY INDEX BECAUSE
OF IT. F1 of the whole-branch review: `_for_insertion` used to build every
probe out of `surface[5]`, so on a templated surface a query, header or
cookie probe went to `/order/{id}/doc` -- an address that cannot exist --
and the 404 came back with nothing reflected, `clean`, `considered`
populated, retiring live findings. The path is now the exemplar's concrete
one, which does NOT contain the placeholder to replace: `str.replace` there
finds nothing, leaves the exemplar's own value in place, and sends a probe
that tests nothing. `_probe_util.substitute_segment` aligns the two paths by
segment index instead, and returns `None` -- a gap, never a silent
substitution-that-did-not-happen -- when it cannot.

A RESPONSE THAT REFUSED IS NOT A CLEAN ONE. A 403, a 429, a 5xx or a 404
reflects nothing for the same reason a properly encoding target reflects
nothing, and the two must not record the same verdict. See `_probe_util.py`
for the doctrine, which all five active checks share.

A REFUSAL BY THE SEND PATH ENDS ONE POINT, NOT THE SURFACE, AND `cookie` IS
STILL DECLARED ON PURPOSE. F2 of the whole-branch review, measured on this
check: `Sender.decide()` refuses any request carrying a `Cookie`,
`Authorization` or `Proxy-Authorization` header the extension did not inject,
`insertion.derive` returns points sorted by `(kind, name)` so `cookie` went
first, and the resulting `ProbeRefused` propagated out of the loop -- so on
any authenticated engagement this check probed NOTHING. Two things changed
and both were needed. `hx.scan.run` no longer hands over a point
`hx.checks.probe.unprobeable` names, so a guaranteed refusal is not attempted
at all; and every send here goes through `_probe_util.send_or_gap`, so a
refusal that DOES arrive -- a rate limit, a spent budget, a halt mid-surface
-- costs its own point and no other. `insertion_kinds` still declares
`cookie` and `header`, and that is not a claim about what gets probed: it is
what makes the runner report `no_probeable_insertion_point` for a surface
whose only points are refused ones, instead of the `no_insertion_point` that
would say this surface had nowhere to put a payload when in truth it had
several. `report._limits` tells the client the same thing.

THE EVIDENCE THIS CHECK CITES is the surface's exemplar exchange, for the
same reason `cors.py` and `open_redirect.py` give: nothing in this build
records a probe's own request and response anywhere, so `surface[6]` is the
only exchange id any of these three checks can truthfully name today.
`report._limits` discloses the gap to the client; closing it for real needs
a new bridge frame type and writer -- Java work beyond this plan, and open
debt owned by no current task.
"""
from __future__ import annotations

from urllib.parse import quote

from hx.checks import base
from hx.checks.active import _probe_util
from hx.checks.passive import _http

# Minted once so a candidate's `issue_type_id` and the verdict's `considered`
# cannot spell it two different ways (the same reasoning `cors.py` and
# `open_redirect.py` give their own `_ISSUE_TYPE`/`_CONSIDERED`). One issue
# type, not one per insertion kind: this check asks the same question --
# "did this come back?" -- everywhere it probes.
_ISSUE_TYPE = "reflected-input"

# The characters that matter for breaking out of an HTML tag, an attribute,
# or a quoted string. Wrapped around a fresh canary for the escalation
# request; see the module docstring's "ESCALATION" section for why these
# four and not a longer, per-character list.
_META_CHARS = "<>\"'"

_PLAIN_TITLE = "Input reflected via {name!r}"
_UNESCAPED_TITLE = "Input reflected via {name!r}, unescaped"


def _for_insertion(path: str, path_template: str, insertion: base.Insertion,
                   value: str) -> tuple[str, dict[str, str]] | None:
    """The path and headers for one probe: `value` in exactly the place
    `insertion` names.

    `path` IS THE ADDRESS AND `path_template` IS ONLY THE MAP. Everything
    sent is built on the exemplar's concrete path; the template is consulted
    for one thing, which segment index a `path_segment` insertion names.

    Query and path segment values are percent-encoded (`quote(..., safe="")`)
    because they ride the request line, the same discipline
    `open_redirect.py`'s `_probe_path` documents; header and cookie values
    are sent verbatim because a header field value is not URL-encoded on the
    wire, and `<`, `>`, `"`, `'` are all legal VCHAR octets there (RFC 9110
    s5.5) -- encoding them would test whether the target un-escapes
    percent-encoding in a header, a different and uninteresting question.

    `path_segment` REPLACES EVERY OCCURRENCE of the placeholder, not just
    the first (`_probe_util.substitute_segment` does, and says why): a
    template repeating `{id}` twice yields ONE `Insertion` for it, both
    occurrences are the same insertion point, and a request still naming the
    real value at the spot a substitution skipped is not the probe this
    check thinks it sent.

    `None` when the substitution could not be made at all -- the caller
    records it as a gap rather than probing an address assembled out of a
    mismatch.
    """
    if insertion.kind == "query":
        return (f"{path}?{quote(insertion.name, safe='')}="
                f"{quote(value, safe='')}", {})
    if insertion.kind == "path_segment":
        substituted = _probe_util.substitute_segment(
            path, path_template, insertion.name, quote(value, safe=""))
        return None if substituted is None else (substituted, {})
    if insertion.kind == "header":
        return path, {insertion.name: value}
    if insertion.kind == "cookie":
        return path, {"Cookie": f"{insertion.name}={value}"}
    raise ValueError(f"unknown insertion kind {insertion.kind!r}")


def _where(resp, marker: str) -> str:
    """A one-line phrase for WHERE `marker` landed, read off the same
    response the caller already has -- NOT `resp.head`/`resp.body` in
    general, `_probe_util.reflected`'s own two halves, so this reports the
    same fact the finding is based on rather than a coincidentally-similar
    one. Not a DOM position -- nothing here parses HTML -- but the coarser
    fact of head vs. body is real evidence a client can act on: a body
    reflection into a document is a different risk from a value merely
    echoed into a response header, and this check must say which it saw
    rather than default to the more alarming-sounding one."""
    needle = marker.encode("ascii")
    in_head = needle in resp.head
    in_body = needle in resp.body
    if in_body and in_head:
        return "both a response header and the response body"
    if in_head:
        return "a response header, not the response body"
    ctype = ", ".join(_http.header_values(resp.head, "content-type"))
    return f"the response body ({ctype or 'no Content-Type header'})"


def _describe(insertion: base.Insertion, marker: str, resp, *,
             unescaped: bool | None) -> str:
    """The finding's own sentences. `unescaped` is THREE-STATE.

    `True` and `False` are the escalation's two answers. `None` is a third
    fact and not a spelling of `False`: the escalation request was REFUSED
    before it was issued (a rate limit, a spent budget, a halt), so nothing
    was learnt about context at all. Saying "they did not come back intact"
    there would be this check reporting a result it never received, which is
    S12's rule applied to one sentence of one finding.
    """
    base_sentence = (
        f"Sending {insertion.kind} {insertion.name!r} with a random, inert "
        f"alphanumeric marker drew back status {resp.status} with that "
        f"marker present in {_where(resp, marker)}, so this target "
        "reflects this input.")
    if unescaped:
        tail = (
            " A second request replaced the marker with a fresh one "
            f"wrapped in {_META_CHARS!r} (the characters that matter for "
            "breaking out of a tag, an attribute, or a quoted string), and "
            "that wrapping came back unescaped and intact.")
    elif unescaped is None:
        tail = (
            " A second request would have replaced the marker with a fresh "
            f"one wrapped in {_META_CHARS!r} to see whether those characters "
            "survive, and it was refused before it was sent, so this check "
            "cannot say whether the surrounding context would let a "
            "character-bearing value through.")
    else:
        tail = (
            " A second request replaced the marker with a fresh one "
            f"wrapped in {_META_CHARS!r} to see whether those characters "
            "survive; they did not come back intact, so this check cannot "
            "say whether the surrounding context would let a "
            "character-bearing value through.")
    honesty = (
        " This shows that input is reflected, not that it is exploitable: "
        "this check only ever sends idempotent GET/HEAD requests, never "
        "renders the response, and never followed up with anything a "
        "browser, script engine or template evaluator would treat as "
        "markup.")
    return base_sentence + tail + honesty


class ReflectedInput:
    id = "hx.active.reflected-input"
    version = "1"
    klass = "active_safe"
    insertion_kinds = frozenset({"query", "path_segment", "header", "cookie"})

    def probes(self, ctx, surface, insertions, sender) -> base.Verdict:
        exemplar_exchange_id = surface[6]
        path_template = surface[5]
        candidates = []
        gaps = []
        probed_any = False

        for insertion in insertions:
            if insertion.kind not in self.insertion_kinds:
                continue

            marker = _probe_util.canary()
            built = _for_insertion(sender.path, path_template, insertion,
                                   marker)
            if built is None:
                # Nothing was sent, so nothing was examined: a gap, and
                # `probed_any` deliberately not set.
                gaps.append(f"{insertion.name}: no probe could be built for "
                            "this insertion point")
                continue
            path, headers = built
            # A REFUSAL ENDS THIS POINT, NOT THE CHECK, and this check is the
            # one F2 of the whole-branch review was measured on: with `cookie`
            # sorting first out of `insertion.derive`, one refusal here used
            # to discard the query and path-segment points that would have
            # worked, on every cookie-bearing engagement. `ProbeSender.get()`
            # still RAISES on every refusal so nothing can read one as a
            # response; `_probe_util.send_or_gap` turns it into a gap for THIS
            # point and lets the loop go on.
            resp = _probe_util.send_or_gap(sender, path, insertion, gaps,
                                           headers=headers)
            if resp is None:
                continue
            probed_any = True
            if not _probe_util.reflected(resp, marker):
                # ASKED ONLY WHERE NOTHING CAME BACK: a canary that reflected
                # proves the response carried this input, whatever its status
                # line said. `_probe_util.verdict`'s "a candidate wins over a
                # gap", one step earlier.
                refusal = _probe_util.unanswered(resp)
                if refusal is not None:
                    gaps.append(f"{insertion.name}: {refusal}")
                continue

            escalation_marker = _probe_util.canary()
            wrapped = f"{_META_CHARS}{escalation_marker}{_META_CHARS}"
            # Not `None`: the same insertion point built a probe a moment ago
            # and `substitute_segment` is a pure function of the same three
            # arguments.
            esc_path, esc_headers = _for_insertion(
                sender.path, path_template, insertion, wrapped)
            # THE FINDING SURVIVES A REFUSED ESCALATION. The first request
            # already proved this input comes back; a refusal on the second
            # costs the CONTEXT answer and nothing else, so `unescaped` goes
            # to `None` -- neither "survived" nor "did not survive" -- and
            # `_describe` says which of the three happened. The gap it
            # records still withholds `considered` (see `_probe_util.
            # verdict`), so the finding is reported and nothing is retired.
            esc_resp = _probe_util.send_or_gap(sender, esc_path, insertion,
                                               gaps, headers=esc_headers)
            unescaped = (None if esc_resp is None
                         else _probe_util.reflected(esc_resp, wrapped))

            title_fmt = _UNESCAPED_TITLE if unescaped else _PLAIN_TITLE
            candidates.append(base.Candidate(
                title=title_fmt.format(name=insertion.name),
                issue_type_id=_ISSUE_TYPE,
                severity="Medium" if unescaped else "Low",
                confidence="Certain",
                insertion=insertion,
                exchange_ids=(exemplar_exchange_id,), cwe="CWE-79",
                description=_describe(insertion, marker, resp,
                                      unescaped=unescaped),
                remediation=(
                    "Encode this input for the context it is reflected "
                    "into (HTML-encode for a body, header-encode for a "
                    "header) before it reaches the response, or drop it "
                    "from the response altogether if it need not be "
                    "echoed at all.")))

        considered = (_ISSUE_TYPE,) if probed_any else ()
        return _probe_util.verdict(candidates, gaps, considered=considered)
