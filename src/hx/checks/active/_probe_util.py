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

THE OTHER FOUR FUNCTIONS ARE HERE FOR A DIFFERENT REASON: not that they
would otherwise be copied, but that five copies would be free to DISAGREE,
and every question they answer is one where a disagreement is a false
`clean`.

  * `substitute_segment` puts a payload in a templated path segment. The
    surface row's `path_template` is `/user/{id}/profile`; the sender is
    bound to the exemplar's concrete `/user/12345/profile`, which is where
    a probe can actually go, and which no longer contains the placeholder to
    replace. Aligning the two by SEGMENT INDEX is the only correct answer
    and it is not obvious -- a check doing `path.replace("{id}", value)`
    against the concrete path silently replaces nothing, sends the
    exemplar's own value back, and calls the result clean.

  * `send_or_gap` is the OTHER refusal doctrine, and it is about the ones
    that never reached the target at all. `ProbeSender` raises on every
    refusal so that no check can read `budget_exhausted` as a response; a
    check that let that propagate out of a per-point loop then discarded
    every point after it, which is F2 of the whole-branch review -- one
    refused cookie took `reflected_input`'s query and path-segment probes
    with it on every cookie-bearing engagement. A refusal ends the POINT
    here, not the check, and lands as a gap, which is what stops the
    surviving points' answers from being written up as a tested surface.

  * `unanswered` and `verdict` are the refusal doctrine. `ProbeSender`
    guarantees only that a complete HTTP response came back; it does not
    and cannot decide whether that response ANSWERED the question. A WAF's
    403, a 500, a 429, a 404 and -- the one that cost the most to see -- a
    302 to a login page are not conclusive negatives, and a check treating
    them as ones records `tested, clean` for a surface it did not test. The
    passive corpus has had this doctrine since `_http.verdict` -- "a gap
    with nothing found is `inconclusive`, never `clean`" -- and `verdict`
    below opens with deliberately the same three branches in the same order,
    including the one that costs the most to get right: a CANDIDATE STILL
    WINS OVER A GAP (a database error legitimately arrives on a 500). It
    then adds one the passive half has no use for: a check whose own filter
    matched nothing SENT nothing, which is neither a gap nor a clean result
    (N3), and a `clean` naming nothing it examined is refused outright
    rather than left to five callers to avoid asking for.

    WHAT THIS DOCTRINE IS AND IS NOT FOR, SINCE FIX ROUND 6. It used to
    guard two things at once: the coverage row (`clean` asserts a test
    happened) and the RETIREMENT that a populated `considered` licensed.
    An active check no longer retires anything at all -- `hx.scan._retirable`
    refuses its `considered` -- so only the first is left, and it is reason
    enough on its own: S12 says a report that cannot tell "tested, clean"
    from "never reached" is worse than no report, and the coverage table is
    where a client reads that distinction.

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
from hx.checks import probe as probe_mod
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


# THE ONLY RESPONSE A CHECK MAY REASON ABOUT IS A 2xx. Everything else is
# not a conclusive negative -- 1xx, 3xx, 4xx, 5xx, a number outside all of
# those, and a status that could not be read at all -- and `unanswered`
# below turns every one of them into a gap.
#
# AN ALLOWLIST, AND THE EIGHTH SPELLING IS WHY IT HAD TO BECOME ONE. This was
# an ENUMERATION of the statuses that refuse -- 400, 401, 403, 404, 405, 429,
# grown one round at a time, then 3xx and 5xx -- so every status nobody had
# thought of read as the application answering. MEASURED at the end of this
# branch, real registry, `scan.run` against a target answering the same
# status to every request on a surface carrying `q`, `redirect_uri` and
# `file`: 422, 410, 407, 406 and 414 each produced five `clean` rows off five
# requests none of which was answered, and `report._coverage` rendered all
# five as tested -- under a Limits bullet telling the client that a rejection
# of the request itself is recorded as `inconclusive`.
#
# 422 IS THE ORDINARY CASE, and the enumeration's own reason for holding 400
# is what makes it one. Every probe this build sends drops the endpoint's
# OTHER query parameters (`ProbeSender._request_bytes` emits a request line,
# a `Host` and at most the one header the check is probing), so a
# multi-parameter endpoint answering a one-parameter probe with a validation
# rejection is the EXPECTED outcome rather than an unusual one -- and
# FastAPI/pydantic spells that rejection 422, as do a great many Rails and
# Node validation layers. That argument was always about the SITUATION and
# never about the number. hx captures browser and XHR traffic, so an
# API-heavy engagement is the ordinary one.
#
# SO THE RULE IS INVERTED RATHER THAN THE LIST WIDENED. An enumeration of
# "bad" statuses has to be MAINTAINED against a web that keeps adding them,
# and every round of that maintenance so far has been a coverage
# overstatement found by a reviewer rather than by the code. "The application
# processed my payload and composed a reply" is a rule instead: it cannot go
# stale, and a status nobody here has considered gets the SAFE treatment by
# construction. It is the shape `hx.checks.probe` already uses twice for this
# same reason -- `_NOT_ISSUED` is an exclusion set so that an unrecognised
# refusal class counts as traffic, and the rate-limit retry allowlists the
# one class worth waiting on so that a new one stays terminal.
#
# WHAT THE EXCLUDED CLASSES MEAN, since a coverage row shows only the number:
#
#   * any 3xx -- the endpoint sent the browser away, and nothing in that
#     response says whether it looked at the probe's parameter at all. N1 of
#     the scoped re-review, and the case that cost the most: every probe this
#     build sends is unauthenticated and the traffic hx captures is browser
#     traffic, so `302 /login` is the COMMONEST shape of the situation this
#     doctrine exists for rather than an edge of it. Read as a conclusive
#     negative it closed all five checks `clean` and -- before fix round 6
#     stopped an active check retiring anything -- brought a live
#     `reflected-input` finding back as `observed = 0`, which
#     `report._findings` renders as "appears fixed; verify before closing".
#   * 400, 413, 414, 415, 422, 431 and their neighbours -- the request was
#     rejected rather than processed, whether for its shape (400), its size
#     (413/414/431), its type (415) or its contents (422). "You sent me
#     nonsense" is not "your payload was safe".
#   * 401, 403, 407 -- a WAF, an expired session, an authorisation layer or a
#     proxy in front of the application. The probe never reached the code
#     under test, and every probe this build sends is unauthenticated, so
#     this is the ordinary answer from an authenticated application rather
#     than an exotic one. A 407 is not composed by the application at all.
#   * 404, 410 -- the resource is gone. Reachable even now that probes go to
#     the exemplar's concrete path: a capture from an hour ago can name a row
#     that has since been deleted.
#   * 405 -- the endpoint declines the only method this build can send. The
#     runner skips a surface this build cannot address before a sender exists
#     (`hx.scan._PROBEABLE_METHODS`), so this is the case that survives that:
#     a surface hx could address whose server answers 405 to the probe built
#     for it.
#   * 429 -- the TARGET's own rate limit, which is a different thing from
#     `hx.policy.Limiter`'s (that one never reaches a check at all; it is a
#     `ProbeRefused`). It means "ask again later", not "there is nothing
#     here".
#   * any 5xx -- the application failed to answer. A maintenance page and a
#     stack trace both carry none of what a check is looking for.
#
# WHAT THE INVERSION COSTS IS COVERAGE AND NEVER A FINDING. All five checks
# ask `unanswered` ONLY where their own match failed, which is the ordering
# F4 put there, so a candidate is decided before this is ever consulted: a
# `Location` naming `open_redirect`'s marker on a 302 and `sql_error`'s
# driver wording on a 500 are findings exactly as they were. What moves is
# the other direction -- a genuine answer delivered on a non-2xx (a 418, an
# API that reports its results under a 4xx) is `inconclusive` where it used
# to be `clean`. That is a surface hx says it could not speak for instead of
# one it wrongly says it tested, which is the direction S12 requires.
#
# NO RULE OVER STATUSES CATCHES A REFUSAL WEARING A 2xx. An application that
# answers a logged-out request with a 200 login PAGE, and an API that reports
# a rejected parameter in a 200 error envelope, are not distinguishable here
# from one that answered. `report._limits` discloses that to the client
# rather than this module pretending otherwise.
_AN_ANSWER = range(200, 300)


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


def send_or_gap(sender, path, insertion, gaps, *, headers=None):
    """One probe: its response, or `None` with a gap recorded.

    A REFUSAL ENDS THIS POINT AND NOT THE CHECK. `ProbeSender.get` RAISES on
    every refusal (`hx/checks/probe.py`, rule one) precisely so that no check
    can read `budget_exhausted` as a response and carry on to `clean`. What
    no check may do with that is let it propagate out of a loop over
    insertion points: the points after the refused one are then never probed,
    and `hx.scan.run` closes the row `inconclusive` for the whole surface.
    MEASURED, F2 of the whole-branch review: on a captured request carrying
    `Cookie: session=...`, `hx.active.reflected-input` probed nothing at all
    -- `insertion.derive` sorts by `(kind, name)`, so the refused cookie went
    first and the query and path-segment points that would have worked were
    never reached.

    CAUGHT HERE AND NOT IN FIVE CHECKS, for the reason the two functions
    below are shared: five copies of this `except` would be five chances to
    spell the gap differently, and one of them to swallow the refusal without
    recording anything -- which is the same false `clean` by another route.

    `exc.reason` IS THE WIRE'S OWN CLASS, not a re-wording. An operator
    reading `budget_exhausted` in a coverage row goes and looks at the run's
    budget; `scope_denied` sends them somewhere else entirely, and a single
    tidy phrase covering both would send them nowhere.

    The honesty is `verdict`'s: a gap turns "found nothing" into
    `inconclusive`, so a surface where one point was refused never records
    `tested, clean` on the strength of the points that did answer.
    """
    try:
        return sender.get(path, headers=headers or {})
    except probe_mod.ProbeRefused as exc:
        gaps.append(f"{insertion.name}: probe refused ({exc.reason})")
        return None


def unanswered(response) -> str | None:
    """Why this response cannot be read as a conclusive negative, or None.

    Short, because it is one entry in a list of at most three that a coverage
    row shows an operator (see `_http._detail`, which formats them). The
    sentence around it is `verdict`'s.
    """
    status = response.status
    if status is None:
        return "no status could be read"
    if status not in _AN_ANSWER:
        return f"status {status}"
    return None


def verdict(candidates, gaps, *,
            examined: tuple[str, ...] = (),
            unprobed: str | None = None) -> base.Verdict:
    """The active corpus's one rule for when `clean` may be said.

    IT OPENS WITH THE SAME THREE BRANCHES AS `_http.verdict`, in the same
    order and for the same reasons -- that module's docstring is the long
    form of those, and the two halves of one corpus answering this question
    differently is the architectural drift this function exists to close.
    Two more follow that the passive half has no use for: a passive check is
    handed this surface's recorded traffic and reads it, so "I examined
    nothing" is not a state it can be in, while an active check decides for
    itself whether any of the points it was handed is worth a request. See
    `unprobed` below. `gaps` is one string per probe that came back without
    answering; `examined` is what the check looked for.

    `examined` IS NOT `Verdict.considered`, AND FIX ROUND 6 IS WHY IT IS
    SPELT DIFFERENTLY. It was that field until this round, and it reached it
    through this function: the four looping checks and `cors` each named
    their issue types here and `hx.scan._mark_unobserved` retired on them.
    An active check now retires nothing at all -- every probe this build
    sends is unauthenticated, and the argument is `hx.scan._retirable`'s --
    so this parameter feeds exactly ONE question: may this check say `clean`
    at all. A check passes the same fact it always did, under a name that no
    longer promises a retirement, and `_retirable` refuses a probing check's
    `considered` outright so the two cannot quietly join up again.

    A CANDIDATE STILL WINS OVER A GAP: what was found was found, and another
    probe on this surface coming back without an answer does not un-find it.
    The gap used to take `considered` off that finding as well, so the
    surface's other issue types were not retired on partial evidence; the
    runner's blanket rule subsumes that, and a finding here is reported with
    nothing withheld from it.

    `unprobed` IS A FOURTH FACT AND IT IS NOT A GAP. A gap is a probe that
    was SENT and came back without answering; `unprobed` is the check saying
    there was nothing here worth sending to at all -- `open_redirect` probes
    only a redirect-shaped parameter name, `path_traversal` only a
    file-shaped one, and a surface whose parameters are `q` and `page` is
    one neither of them examined. `reflected_input` and `sql_error` have no
    name filter, so the runner's `no_insertion_point` skip covers their
    production case; they pass `unprobed` for the KIND guard they apply
    defensively, which the suite drives directly. All four looping checks
    therefore pass it. N3 of the scoped re-review: an unprobed surface used
    to reach the `clean` return with nothing examined, so nothing was
    retired -- the safety envelope held -- but the row read `clean` with
    `requests_sent = 0`, and `report._coverage` groups on (check_id,
    verdict) and counts SURFACES. A real engagement rendered
    `hx.active.open-redirect | clean | <most of the corpus>` for a check
    that probed a handful. `clean` asserts "tested and nothing found"; on
    those rows nothing was tested. S12, on the axis the coverage table is
    for -- which is the axis this whole funnel is left guarding.

    It is ranked BELOW both other branches, and both orderings are real: a
    gap names the wire's own refusal class, which sends an operator
    somewhere the filter sentence would not, and a candidate is a finding
    whatever else did or did not get probed.

    `clean` WITH NOTHING EXAMINED IS REFUSED OUTRIGHT, and that is the
    structural half of the same fix. A check saying "tested, nothing found"
    while naming no issue type it tested FOR is exactly the row N3 is about,
    and there is no caller for which it is the right answer -- so the funnel
    refuses it rather than five callers each remembering not to ask it. That
    is not a hypothetical: adding this raise is what FOUND two of the four
    call sites. `reflected_input` and `sql_error` were expected not to need
    `unprobed` at all, and their own defensive kind guards -- the branch
    each carries because `scan.run` filters by kind and neither check
    assumes it did -- reached this return with nothing examined. The
    doctrine was in one place; the four exits from it were not.
    `hx.scan.run` turns the raise into an `error` row, which no more retires
    anything than any other active row does.

    `_http._detail` FORMATS THE GAP LIST, read across the module boundary
    rather than copied, for the reason `hx.scan._runner_hook` gives for
    reading `registry._RUNNER_CALLS`: the coupling is real -- an operator
    reading a coverage row must see gaps spelt one way whichever half of the
    corpus wrote it -- and naming it is better than owning a second `and N
    more` that can drift.
    """
    if candidates:
        return base.Verdict.finding(*candidates)
    if gaps:
        return base.Verdict.inconclusive(
            "this surface's probes did not all come back as answers, so "
            "nothing found here separates `tested, clean` from `never "
            "reached`" + _http._detail(tuple(gaps)))
    if unprobed is not None:
        return base.Verdict.inconclusive(unprobed)
    if not examined:
        raise ValueError(
            "a clean verdict must name what it examined: nothing was "
            "found, nothing was refused, and no issue type was examined, "
            "which is a check reporting `tested, clean` for a surface it "
            "never tested. Pass `unprobed=<why>` instead")
    return base.Verdict.clean()
