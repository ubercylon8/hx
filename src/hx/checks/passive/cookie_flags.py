"""Session cookies set without the flags that keep them out of reach.

S5 notes that cookie-flag findings have NO INSERTION POINT: the cookie is not
somewhere a payload goes, it is something the response did. `insertion` is
None and `scope_level` is `host`, because a cookie is set for a host and
fixing it fixes every surface under it -- filing one finding per surface would
hand the client the same remediation forty times.
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


def _issue_type(name: str, missing: list[str]) -> str:
    """`cookie-<name>-missing-<flag>[-<flag>...]`, and the name is deliberate.

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

    `missing` is not sorted here: its order comes from one literal tuple in
    `on_surface`, so it is already stable, and re-deriving an order in a
    second place is how two spellings of one identity get born.
    """
    slug = _NOT_KEBAB.sub("-", name.lower()).strip("-") or "unnamed"
    return "-".join(["cookie", slug, "missing", *(f.lower() for f in missing)])


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
                    issue_type_id=_issue_type(name, missing),
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
