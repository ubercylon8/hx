"""Credential-shaped material a response handed back.

DELIBERATELY NARROW. Every pattern here is one whose shape is unambiguous --
a key block header, a vendor key prefix with a fixed length. Entropy
heuristics and `password = "..."` scanning were considered and rejected: they
find real things and they find fifty times as many false ones, and a corpus
that cries wolf is one an operator stops reading.

THE FINDING NEVER REPEATS THE SECRET. A report is the one artifact that leaves
the machine (S12), and a title carrying the credential re-publishes exactly
what redaction removed from the blob one layer down.
"""
from __future__ import annotations

import re

from hx.checks import base
from hx.checks.passive import _http

_PATTERNS = (
    (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
     "a private key block", "High", "CWE-312"),
    (re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
     "an AWS access key id", "High", "CWE-312"),
    (re.compile(rb"\bghp_[A-Za-z0-9]{36}\b"),
     "a GitHub personal access token", "High", "CWE-312"),
    (re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
     "a Slack token", "High", "CWE-312"),
)


class SecretInResponse:
    id = "hx.passive.secret-in-response"
    version = "1"
    klass = "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges) -> base.Verdict:
        seen = _http.bodies(ctx, exchanges)
        if seen is None:
            return base.Verdict.inconclusive(
                "no response body could be read for this surface")

        candidates = []
        for row, body in seen:
            for pattern, what, severity, cwe in _PATTERNS:
                if not pattern.search(body):
                    continue
                candidates.append(base.Candidate(
                    title=f"Response contains {what}",
                    severity=severity, confidence="Firm",
                    insertion=None, scope_level="surface",
                    exchange_ids=(row.id,), cwe=cwe,
                    description=(
                        f"The response body matched the shape of {what}. The "
                        "value itself is deliberately not reproduced here; it "
                        "is in the stored exchange."),
                    remediation="Remove the credential from the response and "
                                "rotate it, in that order.",
                ))
        return base.Verdict.finding(*candidates) if candidates else base.Verdict.clean()
