"""Session cookies set without the flags that keep them out of reach.

S5 notes that cookie-flag findings have NO INSERTION POINT: the cookie is not
somewhere a payload goes, it is something the response did. `insertion` is
None and `scope_level` is `host`, because a cookie is set for a host and
fixing it fixes every surface under it -- filing one finding per surface would
hand the client the same remediation forty times.

THAT SENTENCE WAS A CLAIM ABOUT A FIELD NOTHING READ until F3 of the
whole-branch review. `scope_level` was written to the row and never consulted
when the identity was built, so this check filed exactly the forty tickets it
says here that it does not: MEASURED, one flagless cookie on three surfaces
of one host gave three findings whose keys differed only in `path_template`.
`records.dedupe_key` is where the field is now honoured.
"""
from __future__ import annotations

import re

from hx.checks import base
from hx.checks.passive import _http

# Flags whose absence is worth a finding, and the reason each is conditional.
# `Secure` is demanded only over TLS: a Secure cookie on an http:// origin is
# never sent at all, so demanding it of a target with no TLS is a finding the
# client cannot act on.

_NOT_KEBAB = re.compile(r"[^a-z0-9]+")


def _issue_type(name: str) -> str:
    """`cookie-<name>-flags`. The COOKIE is identity; its missing flags are not.

    THIS CHECK'S ISSUE TYPE CARRIES THE COOKIE IT IS ABOUT, which no other
    check in the corpus needs. `scope_level` is `host`, so the dedupe key's
    `method` and `path_template` are both the literal `-` (see
    `records.dedupe_key`), `insertion` is None per S5, and `type_` is this
    check -- leaving the issue type as the ONLY part of the key that can
    tell two findings apart. Without the name in it, a host setting
    `session` and `csrf` both without HttpOnly files ONE finding, titled for
    whichever cookie the response happened to list first and carrying one of
    the two remediations. That is F1 of the whole-branch review exactly, on
    a different axis, and the two cookies are two edits for the client to
    make.

    THE SET OF MISSING FLAGS IS NOT IN IT, and was until D1 of the fix-round-A
    re-review (MEDIUM). It never bought any discrimination: `on_surface`
    emits exactly ONE candidate per cookie occurrence, carrying ALL of that
    cookie's missing flags, so two candidates for one cookie name cannot
    differ only by flag set. What it did buy is a finding whose identity
    changes as the client fixes it. MEASURED, one cookie over two runs (run
    1 missing HttpOnly, SameSite and Secure; run 2 with SameSite and Secure
    set and HttpOnly still absent): TWO findings, keyed
    `...-missing-httponly-samesite-secure` and `...-missing-httponly`. The
    run-1 row got NO observation row for run 2 -- the check returned
    `finding`, not `clean`, so `scan._mark_unobserved` never considers it --
    so `report._latest_observed` handed back run 1's `True` and the report
    rendered it with no "appears fixed" marker at all, indistinguishable
    from a live finding. The client was told the cookie still lacked
    SameSite and Secure after they had set both, and told it twice.

    The same mechanism bites across SURFACES rather than runs: MEASURED, one
    host with `Secure` set only on `/login`, two host-scoped findings for one
    remediation -- F3's "same remediation forty times" on a new axis, keyed
    on attribute variation instead of path.

    The flag list stays in `title` and `description`, where a reader needs it
    and nothing keys off it.
    """
    slug = _NOT_KEBAB.sub("-", name.lower()).strip("-") or "unnamed"
    return f"cookie-{slug}-flags"


class CookieFlags:
    id = "hx.passive.cookie-flags"
    version = "1"
    klass = "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges) -> base.Verdict:
        seen = _http.responses(ctx, exchanges)
        candidates = []
        for row, head in seen.entries:
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
                    issue_type_id=_issue_type(name),
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
        return _http.verdict(seen, candidates)
