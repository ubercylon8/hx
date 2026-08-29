"""CORS misconfiguration -- the first check that sends.

ONE REQUEST, NO INSERTION POINT. This check carries the cheapest possible
proof that the whole active path works: a single GET carrying an `Origin`
header the target cannot have expected, and the answer sits entirely in the
response headers -- no payload, no reflection analysis over a body, no
insertion point to fill in. `insertion_kinds = frozenset()` on purpose: a
CORS finding has no insertion point because the request is shaped by a
header THIS CHECK adds, not by a parameter it found on the surface. (It is
still handed the exemplar's own concrete path to send that header AT, and
skipped when the surface has no exemplar to cite: "no insertion point" is
not "nothing from the exemplar".) That is the same reasoning S5 gives for
TLS and cookie-flag findings, and it is why `hx.scan.run`'s probe pass runs
a check declaring no kinds instead of skipping it for having none of what it
never asked for (see the comment above `usable = tuple(...)` in `scan.py`).

`_PROBE_ORIGIN` USES `.test`, RFC 2606's reserved TLD for exactly this: a
value guaranteed never to resolve and never to be a real, in-scope
production target, so the check does not have to hope its own probe cannot
collide with the thing it is testing.

WHAT THE PAIR OF HEADERS MEANS, AND WHY THE SEVERITIES DIFFER:

  * `Access-Control-Allow-Origin` reflecting the probe's arbitrary Origin
    VERBATIM, together with `Access-Control-Allow-Credentials: true`, is the
    serious case (`High`): any origin on the internet can read an
    authenticated, cookie-bearing response from this target through a
    victim's browser. This is the shape that turns into cross-origin account
    takeover.
  * The same reflection WITHOUT credentials (`_REFLECTS_NO_CREDENTIALS`,
    `Medium`) is weaker: an arbitrary origin is still trusted, which is a
    real misconfiguration and worth fixing, but there is no session for a
    reflecting attacker to ride -- whatever comes back is no more sensitive
    than what an unauthenticated visitor already sees.
  * `Access-Control-Allow-Origin: *` combined with
    `Access-Control-Allow-Credentials: true` (`_WILDCARD_WITH_CREDENTIALS`,
    `Low`) is a response a conforming browser REFUSES to honour -- the fetch
    spec forbids a wildcard origin from pairing with credentialed mode -- so
    it is a misconfiguration worth reporting to the client (the pairing
    itself is invalid and likely accidental) but not one anything can
    currently exploit through a browser. Lowest severity of the three.
  * `*` alone, with no credentials, is the ordinary shape of a public,
    unauthenticated API and is not reported at all.

THE PROBE GOES TO THE EXEMPLAR'S OWN PATH (`sender.path`), NOT TO THE SURFACE
ROW'S `path_template`. F1 of the whole-branch review: this check used to send
`surface[5]`, which on any templated surface is a string like
`/order/{id}/doc/{uuid}` -- an identity, not an address. The 404 that came
back carried no CORS headers, this check answered `clean` with all three
types in `considered`, and `hx.scan._mark_unobserved` retired the client's
live CORS finding on the strength of it. `hx.checks.probe.ProbeSender` now
refuses a path still carrying a placeholder, so the mistake cannot be made
again silently.

A RESPONSE THAT REFUSED IS NOT A RESPONSE THAT ANSWERED. A 403 from a WAF, a
500, a 429 or a 404 carries no CORS headers for the same reason a correctly
configured target carries none, and the two must not record the same verdict:
`_probe_util.unanswered` names the first, and `_probe_util.verdict` turns it
into `inconclusive` -- which carries no `considered` and therefore retires
nothing. See `_probe_util.py`'s own docstring for why that doctrine is shared
across all five checks rather than spelt here.

`considered` NAMES ALL THREE, on every clean or finding answer, because
`hx.scan._mark_unobserved` retires a finding whose issue type is in
`considered` and was not re-emitted this run: naming fewer than all three
means a client who fixes their CORS header can never see the finding close.

THE EVIDENCE THIS CHECK CITES IS THE SURFACE'S EXEMPLAR EXCHANGE, not a
fresh one from this probe's own request/response. Nothing in this build
records a probe's own request and response anywhere: the extension
captures proxy traffic only (`Capture.deliverExchange` hard-codes
`via: proxy`), and the wire here answers `ProbeSender.get()` directly with
no `hx.capture`-shaped sink wired to it -- so `surface[6]`
(`exemplar_exchange_id`, the exchange that already proved this surface
exists) is the only exchange row this check can truthfully cite: a captured
request TO the affected surface, not the probe that demonstrated the flaw.
That gap is disclosed to the client -- `report._limits` says so (added in
commit 7aa7f63). Closing it for real needs a new bridge frame type and a
new writer, which is Java work outside this plan; it is open debt owned by
no current task.
"""
from __future__ import annotations

from hx.checks import base
from hx.checks.active import _probe_util
from hx.checks.passive import _http

# RFC 2606: `.test` is reserved and guaranteed never to be a real,
# resolvable domain, so this value can never collide with an in-scope
# target -- the check does not have to hope.
_PROBE_ORIGIN = "https://hx-cors-probe.test"

# Distinct, stable, lowercase-kebab identity strings -- IDENTITY, not a
# label (see `base.Candidate`'s own docstring). Each goes in the dedupe key
# and in `finding.issue_type_id`; renaming one later re-files every existing
# finding of that type as new.
_REFLECTS_WITH_CREDENTIALS = "cors-reflects-arbitrary-origin-with-credentials"
_REFLECTS_NO_CREDENTIALS = "cors-reflects-arbitrary-origin"
_WILDCARD_WITH_CREDENTIALS = "cors-wildcard-with-credentials"

# Every issue type this check can conclude about, minted once here so a
# candidate's `issue_type_id` and the verdict's `considered` cannot spell
# the set two different ways.
_CONSIDERED = (
    _REFLECTS_WITH_CREDENTIALS,
    _REFLECTS_NO_CREDENTIALS,
    _WILDCARD_WITH_CREDENTIALS,
)


def _credentials_allowed(values: list[str]) -> bool:
    return any(v.strip().lower() == "true" for v in values)


def _render_header(values: list[str]) -> str:
    """The header's OWN value(s), verbatim -- never inferred. Only correct
    to call where the header is known to be present (every call site below
    is guarded by a branch that already required one of `values` to satisfy
    `_credentials_allowed`), so it never has to guess at absence itself."""
    return ", ".join(values)


def _credentials_phrase(values: list[str]) -> str:
    """What was actually observed for Access-Control-Allow-Credentials, on
    the branch where `_credentials_allowed(values)` is False.

    Fix round 1 (LOW): the description used to hardcode "with no
    Access-Control-Allow-Credentials header" for this branch, which is true
    only when the header is genuinely absent. `_credentials_allowed` also
    answers False for a header that IS present but reads e.g. `False`, a
    typo, or unusual casing beyond exactly `true` -- and a client reading a
    finding that claims "no header" when one was in fact sent is being told
    something false about their own target, from a sentence they cannot
    check against the code that produced it. The two cases are now told
    apart."""
    if not values:
        return "was not present"
    return f"was present but read {', '.join(values)!r}, not the exact `true` a browser honours"


class Cors:
    id = "hx.active.cors"
    version = "1"
    klass = "active_safe"
    insertion_kinds = frozenset()

    def probes(self, ctx, surface, insertions, sender) -> base.Verdict:
        exemplar_exchange_id = surface[6]
        resp = sender.get(sender.path, headers={"Origin": _PROBE_ORIGIN})

        allow_origin = _http.header_values(resp.head,
                                           "access-control-allow-origin")
        origin_value = allow_origin[0] if allow_origin else None
        credential_values = _http.header_values(
            resp.head, "access-control-allow-credentials")
        credentials = _credentials_allowed(credential_values)

        candidate = None
        if origin_value == _PROBE_ORIGIN and credentials:
            candidate = base.Candidate(
                title="CORS reflects an arbitrary Origin with credentials allowed",
                issue_type_id=_REFLECTS_WITH_CREDENTIALS,
                severity="High", confidence="Certain", insertion=None,
                exchange_ids=(exemplar_exchange_id,), cwe="CWE-942",
                payload=_PROBE_ORIGIN,
                description=(
                    f"Requesting with Origin: {_PROBE_ORIGIN} (a value this "
                    "target cannot have expected) drew back "
                    f"Access-Control-Allow-Origin: {origin_value} and "
                    "Access-Control-Allow-Credentials: "
                    f"{_render_header(credential_values)}. Any site on the "
                    "internet can read this target's authenticated, "
                    "cookie-bearing responses through a victim's browser."),
                remediation=(
                    "Validate the Origin header against an explicit "
                    "allowlist of trusted origins before reflecting it, and "
                    "only pair Access-Control-Allow-Credentials: true with "
                    "an origin that was actually validated."))
        elif origin_value == _PROBE_ORIGIN:
            candidate = base.Candidate(
                title="CORS reflects an arbitrary Origin",
                issue_type_id=_REFLECTS_NO_CREDENTIALS,
                severity="Medium", confidence="Certain", insertion=None,
                exchange_ids=(exemplar_exchange_id,), cwe="CWE-942",
                payload=_PROBE_ORIGIN,
                description=(
                    f"Requesting with Origin: {_PROBE_ORIGIN} (a value this "
                    "target cannot have expected) drew back "
                    f"Access-Control-Allow-Origin: {origin_value}. "
                    "Access-Control-Allow-Credentials "
                    f"{_credentials_phrase(credential_values)}. No session "
                    "rides along, but an arbitrary origin is still trusted."),
                remediation=(
                    "Validate the Origin header against an explicit "
                    "allowlist of trusted origins rather than reflecting "
                    "whatever was sent."))
        elif origin_value == "*" and credentials:
            candidate = base.Candidate(
                title="CORS wildcard Origin combined with credentials",
                issue_type_id=_WILDCARD_WITH_CREDENTIALS,
                severity="Low", confidence="Firm", insertion=None,
                exchange_ids=(exemplar_exchange_id,), cwe="CWE-942",
                payload=_PROBE_ORIGIN,
                description=(
                    "The response carried Access-Control-Allow-Origin: * "
                    "together with Access-Control-Allow-Credentials: "
                    f"{_render_header(credential_values)}. A conforming "
                    "browser refuses this pairing, so it is not currently "
                    "exploitable through one, but it is an invalid "
                    "combination and likely an accident worth fixing."),
                remediation=(
                    "Either drop Access-Control-Allow-Credentials or reflect "
                    "a validated, non-wildcard origin instead of *."))

        # ASKED ONLY WHERE NOTHING WAS FOUND, which is `_probe_util.verdict`'s
        # "a candidate wins over a gap" one step earlier: a response carrying
        # `Access-Control-Allow-Origin` answered the question this check asked,
        # whatever its status line said about the rest of the request.
        candidates = [] if candidate is None else [candidate]
        gaps = []
        if not candidates:
            refusal = _probe_util.unanswered(resp)
            if refusal is not None:
                gaps.append(refusal)
        return _probe_util.verdict(candidates, gaps, considered=_CONSIDERED)
