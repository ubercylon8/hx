"""Response headers a document should carry and does not.

DEMANDED OF DOCUMENTS ONLY. A JSON API response cannot be framed and will not
be sniffed into a document, so demanding frame protection of it is noise --
and a corpus that cries wolf on every endpoint is one an operator stops
reading, which costs more than the finding was worth.

THE LAST ELEMENT OF EACH `missing` TUPLE IS IDENTITY, not a label. It
becomes `Candidate.issue_type_id` and the 2nd part of the finding's dedupe
key, and it is what keeps three headers missing from ONE response three
findings rather than one -- F1 of the whole-branch review, which measured
exactly this check filing one row. Renaming one re-files every existing
finding of that type as new, so they are named for the ISSUE and are not to
be tidied.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from hx.checks import base
from hx.checks.passive import _http

_DOCUMENT_TYPES = ("text/html", "application/xhtml+xml")


@dataclass(frozen=True)
class _HeaderSpec:
    """One header this check demands of a document response.

    `issue_type_id` is IDENTITY (see the module docstring); it is minted
    exactly once here and both `on_surface`'s `considered` and its candidates
    read it off this table, so the two cannot spell it two different ways.
    `applies` gates by scheme (HSTS means nothing over plain http); `present`
    reads the response's headers to say whether the requirement is met.
    """
    issue_type_id: str
    title: str
    cwe: str
    severity: str
    applies: Callable[[bool], bool]
    present: Callable[[frozenset, str], bool]


_HEADERS = (
    _HeaderSpec(
        issue_type_id="missing-content-type-options",
        title="X-Content-Type-Options", cwe="CWE-16", severity="Low",
        applies=lambda https: True,
        present=lambda names, csp: "x-content-type-options" in names,
    ),
    # Two headers answer the framing question. Demanding the older one when
    # the newer is present reports something already fixed.
    _HeaderSpec(
        issue_type_id="missing-frame-protection",
        title=("frame protection (X-Frame-Options or CSP "
               "frame-ancestors)"),
        cwe="CWE-1021", severity="Medium",
        applies=lambda https: True,
        present=lambda names, csp: (
            "x-frame-options" in names or "frame-ancestors" in csp),
    ),
    _HeaderSpec(
        issue_type_id="missing-hsts",
        title="Strict-Transport-Security", cwe="CWE-319", severity="Low",
        applies=lambda https: https,
        present=lambda names, csp: "strict-transport-security" in names,
    ),
)


class SecurityHeaders:
    id = "hx.passive.security-headers"
    version = "1"
    klass = "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges) -> base.Verdict:
        seen = _http.responses(ctx, exchanges)
        candidates = []
        considered = []
        for row, head in seen.entries:
            ctype = " ".join(_http.header_values(head, "content-type")).lower()
            if not any(t in ctype for t in _DOCUMENT_TYPES):
                continue
            https = row.url.lower().startswith("https://")
            names = {n.lower() for n in _http.header_names(head)}
            csp = " ".join(_http.header_values(head, "content-security-policy"))

            applicable = [spec for spec in _HEADERS if spec.applies(https)]
            considered.extend(spec.issue_type_id for spec in applicable)
            missing = [spec for spec in applicable
                       if not spec.present(names, csp)]

            for spec in missing:
                candidates.append(base.Candidate(
                    title=f"Missing {spec.title}",
                    issue_type_id=spec.issue_type_id,
                    severity=spec.severity, confidence="Certain",
                    insertion=None, scope_level="surface",
                    exchange_ids=(row.id,), cwe=spec.cwe,
                    description=(
                        f"This document response did not carry {spec.title}."),
                    remediation=f"Set {spec.title} on document responses.",
                ))
            if missing:
                break      # one document per surface is enough to say it
        return _http.verdict(seen, candidates, considered=tuple(considered))
