"""What the five active checks must agree on: canaries, addresses, and when
a response is not an answer.

WHY THE FIRST TWO FUNCTIONS EXIST. `cors.py` and `open_redirect.py` each
mint their own fixed marker (`_PROBE_ORIGIN`, `_MARKER_URL`) because each
needs exactly one string, per check, chosen for what it NAMES -- an Origin
that cannot be the target, a host a `Location` cannot legitimately point at.
Neither would gain anything from a shared minting function: a constant
assigned once is not a helper. `reflected_input.py` is the different case --
it plants one canary per insertion point, on a surface that can hold any
number of them, and needs the *same* two operations (mint a fresh
unmistakable value, then ask whether a response contains it) run once per
point. THAT repetition is what a helper is for; a helper used by one caller
still belongs in its caller, so this module exists only because a second
active check that also needs both operations would otherwise have to copy
them or import from `reflected_input.py` sideways.

THE CANARY IS ALPHANUMERIC ONLY, AND THAT IS THE INERTNESS GUARANTEE. It
cannot close a tag, break out of an attribute, terminate a JSON string, or
open a script context -- there is no character in it capable of being
anything other than itself, wherever it lands. That is what lets a check
built on `canary()` prove reflection happened without ever constructing a
payload: the string that comes back could not have executed no matter what
surrounded it. A caller that wants to learn whether the surrounding context
would let a *different*, character-bearing value survive builds that value
itself, on top of a canary this module minted -- see `reflected_input.py`'s
own escalation step -- because that decision (which characters, and when to
spend the extra request) is specific to what that check is trying to learn,
not something this module can decide on every caller's behalf.

THE OTHER THREE FUNCTIONS ARE HERE FOR A DIFFERENT REASON: not that they
would otherwise be copied, but that five copies would be free to DISAGREE,
and the two questions they answer are the ones where a disagreement is a
false `clean`.

  * `substitute_segment` puts a payload in a templated path segment. The
    surface row's `path_template` is `/user/{id}/profile`; the sender is
    bound to the exemplar's concrete `/user/12345/profile`, which is where
    a probe can actually go, and which no longer contains the placeholder to
    replace. Aligning the two by SEGMENT INDEX is the only correct answer
    and it is not obvious -- a check doing `path.replace("{id}", value)`
    against the concrete path silently replaces nothing, sends the
    exemplar's own value back, and calls the result clean.

  * `unanswered` and `verdict` are the refusal doctrine. `ProbeSender`
    guarantees only that a complete HTTP response came back; it does not
    and cannot decide whether that response ANSWERED the question. A WAF's
    403, a 500, a 429 and a 404 are not conclusive negatives, and a check
    treating them as ones populates `considered` and lets
    `hx.scan._mark_unobserved` retire a live finding. The passive corpus has
    had this doctrine since `_http.verdict` -- "a gap with nothing found is
    `inconclusive`, never `clean`" -- and `verdict` below is deliberately
    the same three branches in the same order, including the one that costs
    the most to get right: a CANDIDATE STILL WINS OVER A GAP (a database
    error legitimately arrives on a 500), and what a gap withholds from a
    finding is `considered`, so the finding is still reported and the
    surface's OTHER issue types are not retired on partial evidence.

RANDOM, PER CALL, AND WHY THAT MATTERS MORE HERE THAN IN EITHER PREDECESSOR.
`records.dedupe_key` folds `insertion_kind`/`insertion_name` into a finding's
identity, so two insertion points that each plant the SAME marker and then
find it reflected cannot be told apart by the marker alone -- only by which
request carried which value. A check that reused one canary across several
insertion points would also risk reading insertion B's echo as insertion A's
answer if the two requests raced or if the target itself echoed something
static that happened to match a fixed string. A fresh random value per call
removes both risks by construction: nothing on the wire ever repeats.
"""
from __future__ import annotations

import secrets
import string

from hx.checks import base
from hx.checks.passive import _http

# Alphanumeric only -- see the module docstring's inertness paragraph. Base62
# rather than hex: more bits of randomness per character, so the same
# collision resistance is reached at a shorter, still-comfortably-readable
# length.
_ALPHABET = string.ascii_letters + string.digits

# 24 characters of base62 is ~142 bits of entropy -- collision with anything
# already on the page, or with another call's own canary, is not a
# realistic concern at any corpus size this tool will ever scan. Short
# enough to survive a field's length limit in the overwhelming common case,
# which a canary that never reflects at all cannot be distinguished from a
# canary that was truncated past recognition.
_LENGTH = 24


def canary() -> str:
    """A fresh, random, purely alphanumeric marker.

    Every call returns a new value -- there is no seed, no counter, and no
    way to ask for the same string twice. A check that needs to tell two
    insertion points' reflections apart calls this once per point, never
    once per surface.
    """
    return "".join(secrets.choice(_ALPHABET) for _ in range(_LENGTH))


def reflected(response, marker: str) -> bool:
    """Whether `marker` appears verbatim anywhere in `response`.

    Checks both halves -- `response.head` and `response.body` -- because a
    value planted in a query parameter, path segment, header or cookie can
    be echoed into either: a diagnostic response header, a `Set-Cookie` that
    mirrors what was sent, or an ordinary place in the body are all
    "reflected" in the sense this module tests for, and a check for the body
    alone would call a target clean for reflecting input straight back in
    its headers.

    A plain substring test, not a parse: `marker` is alphanumeric ASCII (see
    `canary()`), so there is no encoding question a smarter check could get
    right that this one gets wrong, and the response halves are already
    bytes -- nothing here decodes them.
    """
    needle = marker.encode("ascii")
    return needle in response.head or needle in response.body


# The statuses that refuse a request rather than answering it. A check
# receiving one has not tested anything, whatever its payload was:
#
#   * 401/403 -- a WAF, an expired session, an authorisation layer in front
#     of the application. The probe never reached the code under test, and
#     every probe this build sends is unauthenticated -- `ProbeSender.
#     _request_bytes` emits a request line, a `Host` and at most the one
#     header the check is probing -- so this is the ordinary answer from an
#     authenticated application rather than an exotic one.
#   * 404 -- the resource is gone. Reachable even now that probes go to the
#     exemplar's concrete path: a capture from an hour ago can name a row
#     that has since been deleted.
#   * 429 -- the TARGET's own rate limit, which is a different thing from
#     `hx.policy.Limiter`'s (that one never reaches a check at all; it is a
#     `ProbeRefused`). It means "ask again later", not "there is nothing
#     here".
#   * any 5xx -- the application failed to answer. A maintenance page and a
#     stack trace both carry none of what a check is looking for.
#
# 2xx and 3xx are NOT here and must not be: they are the application
# answering, which is what every check needs to reason about -- and
# `open_redirect` reads a 3xx as its FINDING.
_NOT_AN_ANSWER = frozenset({401, 403, 404, 429})


def substitute_segment(path: str, path_template: str, placeholder: str,
                       value: str) -> str | None:
    """`path` with every segment `path_template` calls `placeholder` replaced.

    BY INDEX, NOT BY TEXT. The two strings are the same path read two ways --
    `hx.surface.path_template` splits on `/` and rewrites segments one for
    one, so segment `i` of the template describes segment `i` of the address,
    however differently the two are spelt (a kept segment is decoded and its
    braces escaped; a templated one is replaced outright). A `str.replace` of
    the placeholder against the concrete path finds nothing to replace and
    returns it unchanged, which is a probe carrying the exemplar's own value:
    it tests nothing and reads as clean.

    EVERY OCCURRENCE, not the first. `hx.insertion.derive` collects
    placeholders into a set keyed by name, so a template repeating `{id}`
    twice yields ONE `Insertion` for it -- both occurrences are the same
    insertion point, and a substitution that left one behind would send a
    request still naming the real value at the spot it skipped.

    `None` when the substitution cannot be made -- the two paths disagree
    about how many segments they have, or the template does not carry this
    placeholder at all. Neither should be reachable from a surface whose
    template was derived from this very request, and the caller's answer is
    to record a gap and go `inconclusive` rather than to probe an address it
    assembled out of a mismatch.
    """
    segments = path.split("/")
    template_segments = path_template.split("/")
    if len(segments) != len(template_segments):
        return None
    out, substituted = [], False
    for segment, template_segment in zip(segments, template_segments):
        if template_segment == placeholder:
            out.append(value)
            substituted = True
        else:
            out.append(segment)
    return "/".join(out) if substituted else None


def unanswered(response) -> str | None:
    """Why this response cannot be read as a conclusive negative, or None.

    Short, because it is one entry in a list of at most three that a coverage
    row shows an operator (see `_http._detail`, which formats them). The
    sentence around it is `verdict`'s.
    """
    status = response.status
    if status is None:
        return "no status could be read"
    if status in _NOT_AN_ANSWER or 500 <= status <= 599:
        return f"status {status}"
    return None


def verdict(candidates, gaps, *,
            considered: tuple[str, ...] = ()) -> base.Verdict:
    """The active corpus's one rule for when `clean` may be said.

    THE SAME THREE BRANCHES AS `_http.verdict`, in the same order and for the
    same reasons -- that module's docstring is the long form of this one, and
    the two halves of one corpus answering this question differently is the
    architectural drift this function exists to close. `gaps` is one string
    per probe that came back without answering; `considered` is what the
    check examined.

    A CANDIDATE STILL WINS OVER A GAP: what was found was found, and a probe
    that answered nowhere else does not un-find it. What the gap takes away
    is `considered` -- so the finding is reported and `hx.scan.
    _mark_unobserved` does NOT retire this surface's other findings of the
    same check on the strength of probes that were refused.

    `Verdict.inconclusive` carries no `considered` at all (the classmethod
    does not offer one), so the middle branch retires nothing. That is the
    property doing the safety work here, and it is structural rather than
    remembered.

    `_http._detail` FORMATS THE GAP LIST, read across the module boundary
    rather than copied, for the reason `hx.scan._runner_hook` gives for
    reading `registry._RUNNER_CALLS`: the coupling is real -- an operator
    reading a coverage row must see gaps spelt one way whichever half of the
    corpus wrote it -- and naming it is better than owning a second `and N
    more` that can drift.
    """
    if candidates:
        return base.Verdict.finding(
            *candidates, considered=() if gaps else considered)
    if gaps:
        return base.Verdict.inconclusive(
            "this surface's probes did not all come back as answers, so "
            "nothing found here separates `tested, clean` from `never "
            "reached`" + _http._detail(tuple(gaps)))
    return base.Verdict.clean(considered=considered)

