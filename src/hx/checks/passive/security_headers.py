"""Response headers a document should carry and does not.

DEMANDED OF DOCUMENTS ONLY. A JSON API response cannot be framed and will not
be sniffed into a document, so demanding frame protection of it is noise --
and a corpus that cries wolf on every endpoint is one an operator stops
reading, which costs more than the finding was worth.
"""
from __future__ import annotations

from hx.checks import base
from hx.checks.passive import _http

_DOCUMENT_TYPES = ("text/html", "application/xhtml+xml")


class SecurityHeaders:
    id = "hx.passive.security-headers"
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
            ctype = " ".join(_http.header_values(head, "content-type")).lower()
            if not any(t in ctype for t in _DOCUMENT_TYPES):
                continue
            https = row.url.lower().startswith("https://")
            names = {n.lower() for n in _http.header_names(head)}
            csp = " ".join(_http.header_values(head, "content-security-policy"))

            missing = []
            if "x-content-type-options" not in names:
                missing.append(("X-Content-Type-Options", "CWE-16", "Low"))
            # Two headers answer the framing question. Demanding the older one
            # when the newer is present reports something already fixed.
            if "x-frame-options" not in names and "frame-ancestors" not in csp:
                missing.append(("frame protection (X-Frame-Options or CSP "
                                "frame-ancestors)", "CWE-1021", "Medium"))
            if https and "strict-transport-security" not in names:
                missing.append(("Strict-Transport-Security", "CWE-319", "Low"))

            for title, cwe, severity in missing:
                candidates.append(base.Candidate(
                    title=f"Missing {title}",
                    severity=severity, confidence="Certain",
                    insertion=None, scope_level="surface",
                    exchange_ids=(row.id,), cwe=cwe,
                    description=f"This document response did not carry {title}.",
                    remediation=f"Set {title} on document responses.",
                ))
            if missing:
                break      # one document per surface is enough to say it
        return base.Verdict.finding(*candidates) if candidates else base.Verdict.clean()
