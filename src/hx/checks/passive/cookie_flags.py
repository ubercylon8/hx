"""Session cookies set without the flags that keep them out of reach.

S5 notes that cookie-flag findings have NO INSERTION POINT: the cookie is not
somewhere a payload goes, it is something the response did. `insertion` is
None and `scope_level` is `host`, because a cookie is set for a host and
fixing it fixes every surface under it -- filing one finding per surface would
hand the client the same remediation forty times.
"""
from __future__ import annotations

from hx.checks import base
from hx.checks.passive import _http

# Flags whose absence is worth a finding, and the reason each is conditional.
# `Secure` is demanded only over TLS: a Secure cookie on an http:// origin is
# never sent at all, so demanding it of a target with no TLS is a finding the
# client cannot act on.


class CookieFlags:
    id = "hx.passive.cookie-flags"
    version = "1"
    klass = "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges) -> base.Verdict:
        bodies = _http.responses(ctx, exchanges)
        if bodies is None:
            return base.Verdict.inconclusive(
                "no response body could be read for this surface")

        candidates = []
        for row, head in bodies:
            https = row.url.lower().startswith("https://")
            for cookie in _http.header_values(head, "set-cookie"):
                name = cookie.split("=", 1)[0].strip()
                attrs = {a.strip().split("=", 1)[0].lower()
                         for a in cookie.split(";")[1:]}
                missing = [f for f, want in (("HttpOnly", "httponly"),
                                             ("SameSite", "samesite"),
                                             ("Secure", "secure"))
                           if want not in attrs
                           and (f != "Secure" or https)]
                if not missing:
                    continue
                candidates.append(base.Candidate(
                    title=f"Cookie {name} set without {', '.join(missing)}",
                    severity="Medium" if "HttpOnly" in missing else "Low",
                    confidence="Certain",
                    insertion=None,
                    scope_level="host",
                    exchange_ids=(row.id,),
                    cwe="CWE-1004" if "HttpOnly" in missing else "CWE-614",
                    description=(
                        f"The response set `{name}` without "
                        f"{', '.join(missing)}."),
                    remediation=(
                        "Set the missing attributes on this cookie. HttpOnly "
                        "keeps it out of reach of scripts; SameSite limits "
                        "cross-site submission; Secure prevents it being sent "
                        "over plaintext."),
                ))
        return base.Verdict.finding(*candidates) if candidates else base.Verdict.clean()
