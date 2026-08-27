"""Framework error output returned to the client.

Matched on the SHAPE of a trace, not on the name of an exception: prose
saying "if you see a NullPointerException, contact support" is a help page,
not a leak, and a check that cannot tell them apart files findings against
documentation.
"""
from __future__ import annotations

import re

from hx.checks import base
from hx.checks.passive import _http

_PATTERNS = (
    (re.compile(rb"Traceback \(most recent call last\):"), "a Python traceback"),
    (re.compile(rb"\n\s*at [\w.$]+\([\w.]+\.java:\d+\)"), "a Java stack trace"),
    (re.compile(rb"PHP (?:Fatal|Parse|Warning) error:"), "a PHP error"),
    (re.compile(rb"<title>Server Error in .* Application\.</title>"),
     "an ASP.NET error page"),
    (re.compile(rb"\bat [\w.]+ \(.*?:\d+:\d+\)"), "a Node.js stack trace"),
)


class StackTrace:
    id = "hx.passive.stack-trace"
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
            for pattern, what in _PATTERNS:
                if not pattern.search(body):
                    continue
                candidates.append(base.Candidate(
                    title=f"Response discloses {what}",
                    severity="Low", confidence="Firm",
                    insertion=None, scope_level="surface",
                    exchange_ids=(row.id,), cwe="CWE-209",
                    description=(
                        "The response body carried framework error output, "
                        "which reveals internal paths, versions and code "
                        "structure."),
                    remediation="Return a generic error page and log the "
                                "detail server-side.",
                ))
                break     # one trace per exchange is the finding
        return base.Verdict.finding(*candidates) if candidates else base.Verdict.clean()
