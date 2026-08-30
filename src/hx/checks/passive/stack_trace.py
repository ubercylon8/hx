"""Framework error output returned to the client.

Matched on the SHAPE of a trace, not on the name of an exception: prose
saying "if you see a NullPointerException, contact support" is a help page,
not a leak, and a check that cannot tell them apart files findings against
documentation.

THE THIRD FIELD OF EACH PATTERN IS IDENTITY. It becomes the candidate's
`issue_type_id` and the 2nd part of the finding's dedupe key; the `break`
below keeps one trace per exchange, but a surface with several exchanges can
still disclose a Python traceback on one and a Java one on another, and
those are two findings pointing at two different stacks. Every other part of
the key is fixed by this check and the surface, so without a per-pattern
issue type they would collapse onto one row (F1 of the whole-branch review).
Renaming one re-files existing findings as new.
"""
from __future__ import annotations

import re

from hx.checks import base
from hx.checks.passive import _http

_PATTERNS = (
    (re.compile(rb"Traceback \(most recent call last\):"), "a Python traceback",
     "python-traceback-disclosed"),
    (re.compile(rb"\n\s*at [\w.$]+\([\w.]+\.java:\d+\)"), "a Java stack trace",
     "java-stack-trace-disclosed"),
    (re.compile(rb"PHP (?:Fatal|Parse|Warning) error:"), "a PHP error",
     "php-error-disclosed"),
    (re.compile(rb"<title>Server Error in .* Application\.</title>"),
     "an ASP.NET error page", "aspnet-error-page-disclosed"),
    (re.compile(rb"\bat [\w.]+ \(.*?:\d+:\d+\)"), "a Node.js stack trace",
     "nodejs-stack-trace-disclosed"),
)


class StackTrace:
    id = "hx.passive.stack-trace"
    version = "1"
    klass = "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges) -> base.Verdict:
        seen = _http.bodies(ctx, exchanges)
        candidates = []
        considered = []
        for row, body in seen.entries:
            for pattern, what, issue_type_id in _PATTERNS:
                # `considered` gets this pattern's issue type the moment its
                # `.search()` actually runs -- BEFORE the match is known --
                # so a pattern the `break` below skips for this body is never
                # claimed as examined. A static, `_PATTERNS`-derived
                # `considered` would be wrong here precisely because of that
                # `break`: a body matching the third pattern never reaches
                # the fourth or fifth, so claiming their issue types were
                # considered would let `scan._mark_unobserved` retire a
                # still-live finding of a pattern this body was never
                # checked against.
                considered.append(issue_type_id)
                if not pattern.search(body):
                    continue
                candidates.append(base.Candidate(
                    title=f"Response discloses {what}",
                    issue_type_id=issue_type_id,
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
        return _http.verdict(seen, candidates, considered=tuple(considered))
