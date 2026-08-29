"""Open redirect -- read `Location`, and never, ever follow it.

THE SAFETY RULE THIS CHECK MUST NOT BREAK: never follow the redirect. The
send path is configured `RedirectionMode.NEVER` (S4), so nothing in `hx`
chases a `Location` on its own -- but a check is free to add that behaviour
back by hand, by issuing a *second* `sender.get()` at whatever host the
first response named. That would be a request the operator never
authorised, against a host that may be outside the engagement's scope --
the exact shape S4 exists to prevent. "Follow it to confirm the redirect
really lands off-site" is the obvious next thought and it is WRONG here:
this check reads `Location`, compares its host to the marker it planted,
and stops. It never issues a request whose target came from a response
this check received.

CANARY-FIRST, BECAUSE THE BUDGET IS REAL. `insertions` carries only `kind`
and `name` (`hx.checks.base.Insertion`) -- the surface row `probes()`
receives (`hx.scan._insertions_for`) derives insertion points from the
exemplar request's structure, not its values, so this check has no access
to what a query parameter currently holds. The canary-first filter is
therefore NAME-based: a parameter is probed only when its name contains one
of a small set of tokens (`redirect`, `url`, `uri`, `return`, `next`,
`dest`, `continue`, `target`, `forward`, `goto`, `link`, `callback`,
`navigate`) that redirect-carrying parameters conventionally use --
`redirect_uri`, `returnUrl`, `next`, `continueUrl`, `dest`, and so on. A
parameter named `id`, `page` or `q` cannot plausibly carry a redirect
target and is left alone: probing every query parameter on every surface
would spend the request budget on ones that structurally cannot answer this
question. This is a heuristic, not a proof -- an unconventionally-named
redirect parameter is missed -- but a false negative here costs nothing
worse than the check missing what canary-first was built to accept missing,
while probing every parameter costs a request against the target for every
one of them.

THE MARKER MUST BE UNREACHABLE. `_MARKER_URL` uses `.test`, the TLD RFC
2606 reserves for exactly this purpose: guaranteed never to resolve to a
real, in-scope production host, so a `Location` this check calls a finding
can never actually be reached even if this check is wrong about what it
saw. It intentionally differs from `hx.checks.active.cors._PROBE_ORIGIN`
(same TLD, different label) so a reader correlating traffic from both
checks against one target is never left wondering which check sent which
probe.

WHAT COUNTS AS A FINDING. The probe puts `_MARKER_URL` in the parameter and
reads back the response's status and `Location` (`_http.header_values`,
case-insensitive, exactly like every other header read in this corpus). A
`Location` only means anything on a redirect status (300-399); reading it
off a 200 would be answering a question the response was not asking. Of a
redirect response, `urlsplit(location).hostname` -- which also resolves a
protocol-relative `//host/path` `Location`, a real redirect shape some
servers emit -- decides the case: a host equal (ASCII case-insensitively)
to the marker's is the finding, because nothing the target could have
learned about this engagement could make it redirect there on its own. A
`Location` that is empty, relative (no host at all), or names some other
host is not: the parameter was not used to build the response's target, or
the target validated it, and that is what "clean" says here.

CONSIDERED, NAMED HONESTLY. `_ISSUE_TYPE` is only added to `considered`
when this check actually issued at least one probe on this surface. A
surface with query parameters but none of them canary-shaped, or with no
query insertions at all, is a surface this check never examined for open
redirect, and `hx.scan._mark_unobserved` must not retire a finding on the
strength of a question this check never asked.

THE EVIDENCE THIS CHECK CITES is the surface's exemplar exchange, for the
same reason `cors.py` gives: nothing in this build's probe path writes an
exchange row for a probe's own traffic yet (Task 13's), so
`surface[6]` is the only exchange id this check can truthfully name.

EACH CANDIDATE CARRIES ITS `Insertion`, unlike `cors.py`'s `insertion=None`.
Two parameters on one surface can each independently redirect, and
`records.dedupe_key` folds `insertion_kind`/`insertion_name` into the
finding's identity precisely so those stay two rows instead of colliding
into one -- `_write_finding` in `hx/scan.py` reads `candidate.insertion`
for exactly that pair.
"""
from __future__ import annotations

from urllib.parse import quote, urlsplit

from hx.checks import base
from hx.checks.passive import _http

# RFC 2606: `.test` is reserved and guaranteed never to be a real,
# resolvable domain, so a `Location` naming this host can never actually be
# reached even if this check has misjudged what it saw. Distinct from
# `cors._PROBE_ORIGIN` (same TLD) so probes from the two checks are never
# ambiguous in a traffic capture.
_MARKER_HOST = "hx-open-redirect-probe.test"
_MARKER_URL = f"https://{_MARKER_HOST}/"

# Substrings a query parameter's NAME is checked against, case-insensitively,
# to decide whether it is worth a probe at all -- see the module docstring's
# "CANARY-FIRST" section for why this is name-only. Matches `redirect_uri`,
# `returnUrl`, `next`, `continueUrl`, `dest`, `forward_to`, `goto`, `rlink`,
# `success_callback`, `navigateTo`, and similar; leaves `id`, `page`, `q`,
# `sort` and the like unprobed.
_REDIRECT_NAME_HINTS = (
    "redirect", "url", "uri", "return", "next", "dest", "continue",
    "target", "forward", "goto", "link", "callback", "navigate",
)

# A redirect response's status must claim to be one (RFC 9110 s10.2.2) for
# its `Location` to mean anything at all.
_REDIRECT_STATUSES = range(300, 400)

# Minted once, so a candidate's `issue_type_id` and the verdict's
# `considered` cannot spell the set two different ways (see `cors.py`'s
# identical reasoning for `_CONSIDERED`).
_ISSUE_TYPE = "open-redirect"


def _looks_like_redirect_target(name: str) -> bool:
    low = name.lower()
    return any(hint in low for hint in _REDIRECT_NAME_HINTS)


def _probe_path(path_template: str, name: str, value: str) -> str:
    """The path, with one query parameter carrying the marker.

    `path_template` never carries a query string (`hx.surface.normalise`
    derives it from `parts.path` alone), so this always appends the first
    and only `?`. Percent-encoded by hand -- `ProbeSender.get()` sends
    `path` verbatim onto the request line -- so an unescaped `/` or `:` in
    `_MARKER_URL` cannot be mistaken for structure the wire did not intend.
    """
    return f"{path_template}?{quote(name, safe='')}={quote(value, safe='')}"


def _redirect_host(status: int | None, head: bytes) -> str | None:
    """The `Location` header's host, only where the status makes it one.

    `None` for a non-redirect status, an absent header, or a `Location`
    with no host at all (relative, or unparseable) -- every one of those is
    "this response did not send the browser anywhere the marker could be
    read off", which is exactly the clean case.
    """
    if status not in _REDIRECT_STATUSES:
        return None
    values = _http.header_values(head, "location")
    if not values:
        return None
    # `urlsplit` also resolves a protocol-relative `//host/path` Location,
    # a real redirect shape some servers emit and not merely a relative one.
    return urlsplit(values[0]).hostname


def _location_value(head: bytes) -> str:
    """The `Location` header's own value, verbatim -- never inferred.

    Only correct to call where `_redirect_host` has already established a
    `Location` is present (the one call site below is guarded by exactly
    that), so it never has to guess at absence itself -- the same contract
    `cors._render_header` documents for its own headers.
    """
    return ", ".join(_http.header_values(head, "location"))


class OpenRedirect:
    id = "hx.active.open-redirect"
    version = "1"
    klass = "active_safe"
    insertion_kinds = frozenset({"query"})

    def probes(self, ctx, surface, insertions, sender) -> base.Verdict:
        exemplar_exchange_id = surface[6]
        candidates = []
        probed_any = False

        for insertion in insertions:
            if insertion.kind != "query":
                continue
            if not _looks_like_redirect_target(insertion.name):
                continue
            probed_any = True
            path = _probe_path(surface[5], insertion.name, _MARKER_URL)
            # No `try`/`except` here: `ProbeSender.get()` RAISES
            # `ProbeRefused` on every refusal and never returns one (see
            # `hx/checks/probe.py`), and that is deliberate -- it must
            # propagate out of this method so `hx.scan.run` turns it into
            # `inconclusive`, never something this check mistakes for an
            # answer.
            resp = sender.get(path)

            # THE SAFETY RULE, ENFORCED BY WHAT THIS FUNCTION DOES NOT DO:
            # `_redirect_host` only ever READS `resp.head`. Nothing below
            # this line, or anywhere else in this module, calls
            # `sender.get()` a second time with a target drawn from a
            # response this check received -- that would be following the
            # redirect, and `RedirectionMode.NEVER` exists precisely so a
            # check cannot casually add that back.
            host = _redirect_host(resp.status, resp.head)
            if host is not None and host.lower() == _MARKER_HOST:
                candidates.append(base.Candidate(
                    title=f"Open redirect via {insertion.name!r}",
                    issue_type_id=_ISSUE_TYPE,
                    severity="Medium", confidence="Certain",
                    insertion=insertion,
                    exchange_ids=(exemplar_exchange_id,), cwe="CWE-601",
                    description=(
                        f"Requesting {surface[5]} with {insertion.name}="
                        f"{_MARKER_URL} (a host this target cannot have "
                        f"expected) drew back status {resp.status} with "
                        f"Location: {_location_value(resp.head)}. A browser "
                        "following this response leaves the target for a "
                        "host this check chose, which is what an attacker "
                        "hosting a phishing or credential-harvesting page "
                        "would choose instead."),
                    remediation=(
                        "Validate this parameter against an explicit "
                        "allowlist of destinations (or require same-origin) "
                        "before using it to build a redirect target.")))

        considered = (_ISSUE_TYPE,) if probed_any else ()
        if candidates:
            return base.Verdict.finding(*candidates, considered=considered)
        return base.Verdict.clean(considered=considered)
