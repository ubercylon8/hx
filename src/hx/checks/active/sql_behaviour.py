"""SQL injection read as a DIFFERENCE between two responses, not as a string.

WHY THIS EXISTS, AND IT IS NOT A CRITICISM OF `sql_error`. Measured on
2026-09-02, the first end-to-end run of this harness, against OWASP Juice
Shop: `hx.active.sql-error` probed the `q` parameter of
`/rest/products/search`, the target answered **HTTP 500** -- the injection
firing -- and the check recorded `inconclusive` with the reason
"q: status 500". The engagement reported zero findings.

Nothing was wrong with that. `sql_error` reads a database driver's own
wording out of the response, which is CWE-209 error DISCLOSURE and is a real
issue on its own; a 500 carrying no such wording tells it nothing, and
`_probe_util.unanswered` correctly calls that a gap. The signal was simply
not the kind of signal that check reads.

THE INVERSION, and it is the whole design. Its five sibling checks reason
about response CONTENT -- a reflected canary, a redirect target, an origin
echoed back -- and a non-2xx hands them nothing to reason about, so
`_probe_util.unanswered` treats it as a gap and they are right to. This check
reasons about the DIFFERENCE BETWEEN TWO RESPONSES, and a status change is
the cleanest difference there is. So a 500 here is DATA, and this check
deliberately does not call `unanswered` on either probe. That looks like a
bug against five neighbours, which is why it is written down twice.

WHAT IS SENT: two probes at one insertion point, differing in one character.

    <canary>'       one unbalanced quote -- breaks a string literal
    <canary>''      the escaped form -- valid inside one

Both are built from the same canary so shape and length stay comparable; two
unrelated payloads would make every length delta meaningless. The comparison
is probe-against-probe and NOT probe-against-captured-traffic: the captured
request carried a different value, so its response differs for reasons that
have nothing to do with injection.

WHAT A DIFFERENCE PROVES, AND WHAT IT DOES NOT. It proves the quote reached
something that PARSES it. It does not prove that something is SQL. An input
validator or a WAF that rejects `'` and accepts `''` produces an identical
signal, which is why every candidate here is `Tentative` and says so in as
many words in its own description. Confirming it is a human act -- section 8
forbids the agent from doing it, and the web app exists so a person can.
"""
from __future__ import annotations

from hx.checks import base
from hx.checks.active import _probe_util
from hx import delta as delta_mod

#: One issue type, and it is CWE-89 rather than `sql_error`'s CWE-209. The
#: two checks find different things -- disclosure and behaviour -- and
#: `finding.dedupe_key` carries `issue_type_id`, so a surface exhibiting both
#: files two findings, which is correct: fixing the verbose error page does
#: not fix the injection.
ISSUE_TYPE = "sql-injection-behavioural"

#: A body-length change this small is noise -- a timestamp, a request id, a
#: rotating nonce. Measured against nothing: it is a judgement, deliberately
#: conservative, and `status_changed` is the signal that does not need it.
_MIN_LEN_DELTA = 32


def _probe_values() -> tuple[str, str]:
    """The pair, sharing one canary so their responses are comparable.

    The alphanumeric prefix gives a length- or shape-checked field something
    to accept before either tail reaches a parser -- the reasoning
    `sql_error._probe_value` documents, and the reason both probes carry the
    same one.
    """
    stem = _probe_util.canary()
    return f"{stem}'", f"{stem}''"


def _material(d: dict) -> str | None:
    """What in this delta is worth reporting, or None.

    Returns the human-readable reason so the caller never re-derives it and
    the description cannot describe a different difference from the one that
    fired.
    """
    if d["status_changed"]:
        return "status"
    if abs(d["len_delta"]) >= _MIN_LEN_DELTA:
        return "length"
    # `new_tokens` is None when a body was too large to diff -- NOT empty.
    # Reading None as "no new tokens" would report `clean` for a comparison
    # nobody made, which is section 12's failure in one line.
    if d["new_tokens"]:
        return "content"
    return None


def _describe(insertion: base.Insertion, kind: str,
              quoted: str, escaped: str,
              quote_resp, escaped_resp) -> str:
    """The finding's own account of what was seen and what it is worth.

    THE VALIDATOR SENTENCE IS NOT A HEDGE, it is the finding's accuracy. A
    reader who sees `High` and skips the prose will act on a confirmed
    injection; this paragraph is what stops that being the report's fault.
    """
    differed = {
        "status": (f"the two answers differed in STATUS: "
                   f"{quote_resp.status} against {escaped_resp.status}"),
        "length": (f"the two answers differed in LENGTH by "
                   f"{abs(len(quote_resp.body) - len(escaped_resp.body))} "
                   f"bytes ({quote_resp.status} against "
                   f"{escaped_resp.status})"),
        "content": (f"the two answers differed in CONTENT, with text in one "
                    f"that is absent from the other ({quote_resp.status} "
                    f"against {escaped_resp.status})"),
    }[kind]
    return (
        f"Two requests were sent to {insertion.kind} point "
        f"{insertion.name!r}, differing in one character: {quoted!r}, "
        f"which leaves a string literal unterminated, and {escaped!r}, "
        f"which is the same value with the quote escaped and is valid "
        f"inside one. {differed}.\n\n"
        f"A value that changes an application's behaviour only when its "
        f"quote is unbalanced has reached something that parses SQL "
        f"quoting.\n\n"
        f"**This is a Tentative finding and needs a human to confirm it.** "
        f"The difference proves the quote reached a PARSER; it does not "
        f"prove that parser is a database. An input validator or a WAF that "
        f"rejects a bare quote and accepts an escaped one produces exactly "
        f"this signal and is not a vulnerability. Reproduce both requests by "
        f"hand before reporting this to a client: if the unbalanced quote "
        f"draws a database error, a boolean condition changes the result "
        f"set, or a deliberately false condition empties it, the injection "
        f"is real; if it draws a uniform rejection page, it is input "
        f"validation working.")


class SqlBehaviour:
    id = "hx.active.sql-behaviour"
    version = "1"
    klass = "active_safe"
    insertion_kinds = frozenset({"query", "path_segment"})

    def probes(self, ctx, surface, insertions, sender) -> base.Verdict:
        exemplar_exchange_id = surface[6]
        path_template = surface[5]
        candidates = []
        gaps = []
        probed_any = False

        for insertion in insertions:
            if insertion.kind not in self.insertion_kinds:
                continue

            quoted, escaped = _probe_values()
            paths = []
            for value in (quoted, escaped):
                path = _probe_util.probe_path(sender.path, path_template,
                                              insertion, value,
                                              check_id=self.id)
                if path is None:
                    paths = []
                    gaps.append(f"{insertion.name}: no probe could be built "
                                "for this insertion point")
                    break
                paths.append(path)
            if not paths:
                continue

            # BOTH HALVES OR NEITHER. The comparison is the finding; one
            # probe alone is a bare status with nothing to read it against,
            # and a lone 500 is exactly the non-signal that sent this check
            # into existence. A refusal on either therefore ends this point
            # -- and only this point, the rule `send_or_gap` documents.
            quote_resp = _probe_util.send_or_gap(sender, paths[0],
                                                 insertion, gaps)
            if quote_resp is None:
                continue
            escaped_resp = _probe_util.send_or_gap(sender, paths[1],
                                                   insertion, gaps)
            if escaped_resp is None:
                continue
            probed_any = True

            # NO `_probe_util.unanswered` CALL, and the module docstring's
            # "THE INVERSION" paragraph is why. A non-2xx is this check's
            # signal, not its blind spot.
            d = delta_mod.against(escaped_resp.status, escaped_resp.body,
                                  quote_resp.status, quote_resp.body)
            kind = _material(d)
            if kind is None:
                # NO DIFFERENCE IS NOT AUTOMATICALLY `clean`, and this branch
                # was missing until `test_every_probing_check_reads_a_login_
                # wall_as_a_gap` refused to let a sixth check join without it.
                # Against a target that 302s everything, both probes come back
                # identical, `_material` says None, and the naive version of
                # this check reports `tested, clean` for a surface it never
                # reached -- section 12's exact failure.
                #
                # `unanswered` IS consulted here and nowhere else in this
                # check, and the distinction is the design. It is not asked
                # whether a probe answered before the comparison, because a
                # 500 is this check's signal. It is asked AFTER, only when
                # there was nothing to compare, because two identical
                # refusals refuse both spellings of the payload and separate
                # nothing.
                if (_probe_util.unanswered(quote_resp) is not None
                        and _probe_util.unanswered(escaped_resp) is not None):
                    gaps.append(
                        f"{insertion.name}: both probes came back "
                        f"{quote_resp.status} and identical, so nothing here "
                        "separates `tested, clean` from `never reached` -- an "
                        "endpoint that refuses every request refuses an "
                        "unbalanced quote and an escaped one alike")
                continue

            candidates.append(base.Candidate(
                title=(f"Possible SQL injection via {insertion.name!r} "
                       "(behavioural)"),
                issue_type_id=ISSUE_TYPE,
                severity="High", confidence="Tentative",
                insertion=insertion,
                exchange_ids=(exemplar_exchange_id,), cwe="CWE-89",
                payload=quoted,
                description=_describe(insertion, kind, quoted, escaped,
                                      quote_resp, escaped_resp),
                remediation=(
                    "Build every query with parameterised statements or "
                    "prepared statements, so that a value can never change "
                    "the shape of the statement it travels in. Escaping "
                    "quotes by hand is not equivalent: it has to be right "
                    "everywhere, and a single missed call restores the "
                    "flaw.")))

        if not probed_any:
            return _probe_util.verdict(candidates, gaps,
                                       unprobed=self._nothing_probeable())
        return _probe_util.verdict(candidates, gaps, examined=(ISSUE_TYPE,))

    def _nothing_probeable(self) -> str:
        """What a coverage row says for a surface nothing was sent to."""
        return ("no insertion point on this surface is one this check "
                "probes -- it probes "
                f"{', '.join(sorted(self.insertion_kinds))} points -- so "
                "nothing was sent and this surface was not examined for "
                "behavioural SQL injection")
