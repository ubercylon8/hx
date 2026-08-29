"""CORS misconfiguration -- the first check that sends.

ONE REQUEST, NO INSERTION POINT. This check carries the cheapest possible
proof that the whole active path works: a single GET carrying an `Origin`
header the target cannot have expected, and the answer sits entirely in the
response headers -- no payload, no reflection analysis over a body, nothing
to derive from an exemplar. `insertion_kinds = frozenset()` on purpose: a
CORS finding has no insertion point because the request is shaped by a
header THIS CHECK adds, not by a parameter it found on the surface. That is
the same reasoning S5 gives for TLS and cookie-flag findings, and it is why
`hx.scan.run`'s probe pass runs a check declaring no kinds instead of
skipping it for having none of what it never asked for (see the comment
above `usable = tuple(...)` in `scan.py`).

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

`considered` NAMES ALL THREE, on every clean or finding answer, because
`hx.scan._mark_unobserved` retires a finding whose issue type is in
`considered` and was not re-emitted this run: naming fewer than all three
means a client who fixes their CORS header can never see the finding close.

THE EVIDENCE THIS CHECK CITES IS THE SURFACE'S EXEMPLAR EXCHANGE, not a
fresh one from this probe's own request/response. Nothing in this build's
probe path writes an exchange row for a probe's own traffic yet -- the wire
answers `ProbeSender.get()` directly, and no `hx.capture`-shaped sink is
wired to it -- so `surface[6]` (`exemplar_exchange_id`, the exchange that
already proved this surface exists) is the only exchange row this check can
truthfully cite. Recording the probe's own exchange is Task 13's.
"""
from __future__ import annotations

from hx.checks import base
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


def _credentials_allowed(head: bytes) -> bool:
    values = _http.header_values(head, "access-control-allow-credentials")
    return any(v.strip().lower() == "true" for v in values)


class Cors:
    id = "hx.active.cors"
    version = "1"
    klass = "active_safe"
    insertion_kinds = frozenset()

    def probes(self, ctx, surface, insertions, sender) -> base.Verdict:
        exemplar_exchange_id = surface[6]
        resp = sender.get(surface[5], headers={"Origin": _PROBE_ORIGIN})

        allow_origin = _http.header_values(resp.head,
                                           "access-control-allow-origin")
        origin_value = allow_origin[0] if allow_origin else None
        credentials = _credentials_allowed(resp.head)

        candidate = None
        if origin_value == _PROBE_ORIGIN and credentials:
            candidate = base.Candidate(
                title="CORS reflects an arbitrary Origin with credentials allowed",
                issue_type_id=_REFLECTS_WITH_CREDENTIALS,
                severity="High", confidence="Certain", insertion=None,
                exchange_ids=(exemplar_exchange_id,), cwe="CWE-942",
                description=(
                    f"Requesting with Origin: {_PROBE_ORIGIN} (a value this "
                    "target cannot have expected) drew back "
                    f"Access-Control-Allow-Origin: {origin_value} and "
                    "Access-Control-Allow-Credentials: true. Any site on the "
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
                description=(
                    f"Requesting with Origin: {_PROBE_ORIGIN} (a value this "
                    "target cannot have expected) drew back "
                    f"Access-Control-Allow-Origin: {origin_value} with no "
                    "Access-Control-Allow-Credentials header. No session "
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
                description=(
                    "The response carried Access-Control-Allow-Origin: * "
                    "together with Access-Control-Allow-Credentials: true. "
                    "A conforming browser refuses this pairing, so it is not "
                    "currently exploitable through one, but it is an invalid "
                    "combination and likely an accident worth fixing."),
                remediation=(
                    "Either drop Access-Control-Allow-Credentials or reflect "
                    "a validated, non-wildcard origin instead of *."))

        if candidate is not None:
            return base.Verdict.finding(candidate, considered=_CONSIDERED)
        return base.Verdict.clean(considered=_CONSIDERED)
