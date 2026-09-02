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

from hx.checks import base
from hx.checks.passive import _http

# Flags whose absence is worth a finding, and the reason each is conditional.
# `Secure` is demanded only over TLS: a Secure cookie on an http:// origin is
# never sent at all, so demanding it of a target with no TLS is a finding the
# client cannot act on.

# The bytes a cookie name keeps as themselves inside `issue_type_id`.
# Everything else -- INCLUDING `%` itself, and including the `|` that
# separates the parts of `finding.dedupe_key` -- is escaped by `_encode_name`.
_SAFE = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._")


def _encode_name(name: str) -> str:
    """A cookie name, escaped so TWO NAMES CAN NEVER SHARE ONE ENCODING.

    D4 of the fix-round-A re-review (LOW, and it dropped a finding in
    silence). The transform here was `[^a-z0-9]+ -> "-"`, lowercased,
    stripped, `or "unnamed"`. It was LOSSY in four ways, each of which merges
    two real cookies into one stored finding while `summary.findings` counts
    both: `session_id` and `session.id` (punctuation classes collapse);
    `Session` and `session` (RFC 6265 makes a cookie name case-SENSITIVE, so
    those are two cookies); `__Host-a` and `__host_a`; and every
    all-punctuation name onto the literal `unnamed`, which a cookie may also
    simply be called. That is F1 of the whole-branch review verbatim -- the
    chimera row, the second candidate's severity on the first's title -- on
    the one check whose `issue_type_id` was supposed to close it, and the
    dropped finding is silent.

    THE ESCAPE, and why it cannot collide. The name is taken to UTF-8 bytes;
    each byte is either one `_SAFE` character, spelled as itself, or three
    characters `%XX` with XX its uppercase hex. That per-byte code is
    PREFIX-FREE and one-to-one: a `%` escape is the only code that starts
    with `%` (`%` is not in `_SAFE`, so a literal `%` in a name is `%25`),
    and every other code is a single non-`%` character. A concatenation of
    codes from a prefix-free one-to-one code is uniquely decodable, so the
    byte string can be read straight back off the encoding; UTF-8 is
    one-to-one on names; therefore two distinct names cannot encode alike.
    The fixed `cookie-` prefix and `-flags` suffix `_issue_type` wraps it in
    are constants, which cannot make two distinct middles equal.

    NOT A HASH, and not a slug-plus-truncated-digest. A digest short enough
    to read is short enough to collide, and this value is IDENTITY -- a
    collision here is two clients' cookies sharing one ticket, silently,
    which is the defect rather than a fix for it. Escaping keeps the common
    case literally readable (`cookie-session_id-flags`, `cookie-JSESSIONID-flags`)
    and pays three characters only for the bytes that are genuinely unusual
    in a name.

    THE LOSSY VERSION WAS STILL RIGHT ABOUT ONE THING: attacker-influenced
    bytes must not reach the dedupe key raw, because `|` is that key's
    separator and a cookie named `a|b` could otherwise forge a key belonging
    to another finding. `|` is not in `_SAFE`, so it becomes `%7C`, and so
    does every other byte outside the set.

    An empty name (a response of `Set-Cookie: =v`) encodes to the empty
    string and needs no placeholder: it is the only name that does, which is
    exactly what `or "unnamed"` broke.
    """
    return "".join(
        chr(b) if chr(b) in _SAFE else f"%{b:02X}"
        for b in name.encode("utf-8", "surrogatepass"))


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

    The name is spelled by `_encode_name`, which is INJECTIVE and preserves
    case: identity is worth nothing if two different cookies can reach the
    same one.
    """
    return f"cookie-{_encode_name(name)}-flags"


class CookieFlags:
    id = "hx.passive.cookie-flags"
    version = "1"
    looks_for = ("cookies set without the Secure, HttpOnly or SameSite flags")
    klass = "passive"
    insertion_kinds = frozenset()

    def on_surface(self, ctx, surface, exchanges) -> base.Verdict:
        seen = _http.responses(ctx, exchanges)
        candidates = []
        considered = []
        for row, head in seen.entries:
            https = row.url.lower().startswith("https://")
            for cookie in _http.header_values(head, "set-cookie"):
                name = cookie.split("=", 1)[0].strip()
                # Minted once per cookie occurrence and reused for both the
                # candidate and `considered`, so the two cannot drift: a
                # candidate whose issue type is not in `considered` is never
                # retired, and nothing else would notice.
                issue_type = _issue_type(name)
                considered.append(issue_type)
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
                    issue_type_id=issue_type,
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
        return _http.verdict(seen, candidates, considered=tuple(considered))
