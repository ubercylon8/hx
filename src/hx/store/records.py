"""What the send path did: denial rows and exchange rows.

The extension has no database access by design -- the jar's dependency list is
deliberately empty and nothing inside Burp's JVM should be able to write the
evidence store -- so every row the send path produces is written from here.
Spec S4: "Any denial produces a `denial` row and a distinct error class.
Denials are never silent."

Both writers are keyword-only, and a positional call site that drifted by one
argument would file evidence against the wrong run without any type error to
show for it.

COUNTED, because this paragraph had both numbers wrong. The two INSERTs name
**26** columns -- 10 on `denial`, 16 on `exchange` -- not twenty-one; 23 is the
number of KEYWORD PARAMETERS the two writers take between them (9 and 14),
which is a different thing and the likely source of the error. (25/21/8/13
until Plan 4 gave both writers a `via`, and `denial` the column to put it in.
The numbers move; that they are DERIVED rather than transcribed is the point.)
And **five** of
those parameters are nullable ids of the same shape, not six:
`record_denial.run_id`, `record_denial.scope_version_id`,
`record_exchange.run_id`, `record_exchange.surface_id` and
`record_exchange.scope_version_id`. (`req_blob` and `resp_blob` are `str |
None` too and are deliberately not in that five: a blob digest is not a row id
and confusing one for the other is not the mistake this warns about.) A test
derives all three numbers rather than trusting this comment again.

Neither writer opens a transaction. Each is a single INSERT (or a single
UPDATE), which is atomic on its own under `db.connect`'s autocommit
connection; a caller writing an exchange row and its blobs together should
wrap the pair in `db.transaction` itself.

BOTH WRITERS REDACT THE URL THEY ARE GIVEN. §7 keeps credentials out of the
store, and until 2026-08-26 its whole mechanism was header names and injected
byte ranges inside the JVM -- so a credential in the request TARGET
(`http://user:pass@host/`) reached `exchange.url` and `denial.url` untouched.
`redact_url` is that boundary, and it is at the WRITER rather than at
`hx.capture` so that it covers the callers this plan has not written yet. See
its docstring for the rule, and for the half of the finding it does not close.
"""
from __future__ import annotations

import sqlite3
import uuid

from hx.store.db import transaction

# Error class (spec S6) -> the `kind` value the denial table's CHECK
# constraint accepts. The vocabulary is Plan 1's and cannot be widened from
# here: an unrecognised kind is refused by SQLite itself, so this map is the
# only supported way to get from a bridge error to a row.
DENIAL_KIND: dict[str, str] = {
    "scope_denied": "scope",
    "method_denied": "method",
    "dangerous_denied": "dangerous",
    "rate_limited": "rate",
    "budget_exhausted": "budget",
    "not_configured": "not_configured",
    # Added 2026-08-25 with SCHEMA_VERSION 6, closing the gap the comment on
    # UNRECORDABLE called "the gap to close first". S4 is unconditional and
    # this class was the one denial the vocabulary could not express, so it
    # reached `hx.capture` and vanished silently. S7's "never persisted" is
    # about the request bytes; the refusal is a denial like any other.
    "unmanaged_credential": "credential",
}
DENIAL_KINDS = frozenset(DENIAL_KIND.values())

# The prefix a `not_configured` detail carries when the EXTENSION is at fault
# rather than the operator.
#
# `not_configured` is overloaded: "an operator has not authorised this run
# yet" and "this jar is broken" are opposite instructions and share one class.
# docs/bridge-protocol.md's class list records the overload; S6's names the
# class and nothing more. Both map to
# kind='not_configured' above, so without this
#
#     SELECT kind, COUNT(*) FROM denial GROUP BY kind
#
# reads a crashed send path as an unauthorised run. Splitting the CLASS needs
# an S6 amendment; the detail carries it today, and a prefix carries it in a
# form a consumer can test for. `BridgeClient.EXTENSION_FAULT` is the same
# string on the Java side, and a test pins the pair.
EXTENSION_FAULT = "extension fault: "

# What `redact_url` writes over a request target's userinfo.
#
# THE SAME STRING `Redactor.OBSERVED_USERINFO` writes into the BLOB, byte for
# byte, and `tests/test_credentials_never_reach_the_store.py` reads it out of
# the .java file and compares. §7's placeholders are a wire-visible vocabulary:
# a `url` column saying one thing and the request blob beside it saying another
# is two spellings of one fact, and a report that joins them shows two.
#
# A `str`, not a container, so the module-level vocabulary scan in
# `tests/test_vocabularies_match_the_schema.py` does not see it -- and it has
# no schema CHECK to be paired against either, because no column enumerates it.
# It is pinned against the Java constant instead, which is the copy that can
# actually drift.
OBSERVED_USERINFO = "{{observed:userinfo}}"

# What `redact_url` writes over a credential parameter's VALUE. The name and
# the `=` are kept -- `surface.query_key_set` reads the KEY, and a redaction
# that moved a key would change which surface a request belongs to.
#
# `Redactor.OBSERVED_PARAM` is the same string, pinned by the same test that
# pins OBSERVED_USERINFO.
OBSERVED_PARAM = "{{observed:param}}"

# Query-parameter names whose VALUE is a credential, lower-cased.
#
# A FIXED LIST OF NAMES, MATCHED WHOLE AND CASE-INSENSITIVELY, and the whole
# design is in `Redactor.CREDENTIAL_PARAMS` -- including which names are
# deliberately ABSENT (`code`, `state`, `nonce`, `csrf`) and why, and what the
# ambiguous entries cost. This is the second copy of that vocabulary and it is
# COMPARED against the first rather than trusted: a test reads the array out of
# Redactor.java and requires the two sets to be equal. A name added on one side
# only is a leak on the other, and it is exactly the drift
# `tests/test_vocabularies_match_the_schema.py` exists to refuse -- one
# artifact further out, because these two places are two LANGUAGES.
#
# IT IS INCOMPLETE BY CONSTRUCTION. It catches well-known names and NOT a
# client's own name for a token: `?acme_session=` reaches this column and the
# blob store verbatim, and a test asserts that rather than a comment claiming
# it. The route out is an operator-declared list in the engagement config,
# which needs a config schema change AND a `configure` wire key -- an
# unrecognised `configure` key is a hard `bad_config` today, so there is no
# wire for it either.
CREDENTIAL_PARAMS = frozenset({
    "access_token", "refresh_token", "id_token", "auth_token", "token",
    "jwt",
    "api_key", "apikey", "api-key", "key",
    "secret", "client_secret",
    "password", "passwd", "pwd",
    "auth", "authorization",
    "sig", "signature",
    "session", "sessionid", "sid",
    "x-amz-signature", "x-amz-credential", "x-amz-security-token",
})


def redact_url(url: str) -> str:
    """A url with the userinfo of its authority replaced. §7.

    THE COLUMN HALF OF THE SAME FINDING THE EXTENSION'S JOB 5 CLOSES IN THE
    BLOB. `http://user:pass@app.test/` reached `exchange.url` and `denial.url`
    verbatim. A column is deletable where a content-addressed blob is not, so
    this is the lesser half -- but two halves of one request redacted by two
    different rules is how a report ends up quoting the credential out of the
    column beside the blob that does not have it.

    THE RULE IS RFC 3986 AND NOTHING ELSE. 3.2: the authority follows `//` and
    ends at the next `/`, `?` or `#`, or at the end. 3.2.1:
    `authority = [ userinfo "@" ] host [ ":" port ]`. 2.2: `@` is a gen-delim,
    and neither a host nor a port may contain one. So an `@` inside an
    authority IS the userinfo delimiter; nothing here guesses whether what
    precedes it looks like a secret, because the RFC has already said that is
    where one goes.

    `urlsplit` is deliberately NOT used. It would parse and this would then
    have to re-assemble, and `urlunsplit` normalises -- it drops an empty
    query's `?`, and re-joins a fragment this store has no reason to move.
    `exchange.url` is EVIDENCE: the only edit it may carry is the one this
    function is for. So the rule is applied to the string in place, which also
    makes it the same rule the Java side applies to a request line, character
    for character. They are compared over one shared vector file.

    THE LAST `@` IN THE AUTHORITY, matching `urlsplit`'s own `rpartition('@')`
    and the WHATWG URL parser. A conforming userinfo pct-encodes its own `@`,
    so the two rules differ only on a malformed authority carrying two -- and
    taking the first would leave the bytes between them verbatim.

    WHAT IT DOES NOT TOUCH, named here because §7's mechanisms are only worth
    what their exclusions are:

      - A CREDENTIAL IN A QUERY PARAMETER THIS LIST DOES NOT NAME. The
        VALUES of `CREDENTIAL_PARAMS` are replaced -- `?access_token=` is
        redacted -- and a client's own name for a token is NOT:
        `?acme_session=` reaches this column verbatim. Names, never shapes: a
        rule that redacted what looks opaque would rewrite `?id=1001` and
        corrupt the exact evidence an access-control check reads. The limit
        is pinned by a test using a made-up parameter name, so it is a
        measured fact and not a caveat that can be quietly widened.
      - A NON-CREDENTIAL PARAMETER'S VALUE, which is the point of the list
        existing at all. `?id=1001` survives byte for byte.
      - A PERCENT-ENCODED NAME (`%61ccess_token`), a pair separated by `;`
        rather than `&`, and a credential nested inside another parameter's
        value. See `Redactor.addCredentialParamCuts` for each.
      - An `@` in the PATH, the QUERY or the FRAGMENT. RFC 3986 3.3 allows one
        there and `/users/alice@example.test` is a real path segment.
      - A url with no `://` at all. There is no authority to find.
    """
    cuts = _userinfo_cuts(url) + _credential_param_cuts(url)
    if not cuts:
        # The common url, returned by identity. Anything with nothing to
        # redact must come back byte for byte.
        return url
    cuts.sort()
    out = []
    at = 0
    for start, end, with_ in cuts:
        # Overlap is DROPPED, not merged, exactly as the Java side does it and
        # for the same input: `?access_token=http://u:p@h/` nests a userinfo
        # cut inside a parameter-value cut, and sorted by start the outer one
        # has already consumed it.
        if start < at:
            continue
        out.append(url[at:start])
        out.append(with_)
        at = end
    out.append(url[at:])
    return "".join(out)


def _userinfo_cuts(url: str) -> list[tuple[int, int, str]]:
    """The userinfo of the first URI in `url`, as a (start, end, text) cut.

    The cut ENDS at the `@` rather than past it, so the `@` survives and the
    result still reads as an authority.
    """
    scheme = url.find("://")
    if scheme < 0:
        return []
    start = scheme + 3
    end = start
    # The authority's own terminators, plus the whitespace that ends a request
    # target inside a request line. The whitespace half is redundant for a url
    # column and is here so that this rule and the extension's are ONE rule:
    # a difference the shared vectors cannot reach is still a difference.
    while end < len(url) and url[end] not in "/?# \t\r\n":
        end += 1
    at = url.rfind("@", start, end)
    if at < 0:
        return []
    return [(start, at, OBSERVED_USERINFO)]


def _credential_param_cuts(url: str) -> list[tuple[int, int, str]]:
    """The VALUES of `CREDENTIAL_PARAMS` in the query, as cuts.

    RFC 3986 3.4: the query begins at the FIRST `?` and runs to the next `#`
    or the end. `?` is a gen-delim and not a `pchar`, so it cannot appear
    unencoded in a path and the first one really is the delimiter. Inside a
    request LINE the target also ends at the SP before the HTTP-version, so
    whitespace ends the scan too -- the same terminator set the extension
    uses, because these are one rule in two languages.

    `parse_qsl` is deliberately NOT used, twice over: it DECODES, and this
    function has to return the byte offsets of the raw text so the rest of the
    url survives verbatim; and it drops what it cannot parse, which would
    silently leave a malformed pair carrying a credential untouched.

    A pair with no `=` has no value to redact. An EMPTY value is left alone
    for the reason job 3 leaves a deletion cookie's empty value: an empty
    value cannot be a credential, and a placeholder would read as an issuance.
    """
    q = url.find("?")
    if q < 0:
        return []
    end = q + 1
    while end < len(url) and url[end] not in "# \t\r\n":
        end += 1
    cuts: list[tuple[int, int, str]] = []
    p = q + 1
    while p < end:
        amp = url.find("&", p, end)
        if amp < 0:
            amp = end
        eq = url.find("=", p, amp)
        if eq >= 0 and eq + 1 < amp and url[p:eq].lower() in CREDENTIAL_PARAMS:
            cuts.append((eq + 1, amp, OBSERVED_PARAM))
        p = amp + 1
    return cuts

# Error class (spec S6) -> the `outcome` the exchange table accepts WHEN THE
# REQUEST WAS ISSUED. Two of the four entries are never issued; the other two
# are sometimes, and the class alone does not say which. This comment has now
# been wrong twice, in the same direction both times:
#
#   timeout, bridge_lost    "the request DID leave the JVM. Something answered
#                           late, or the peer went away with it in flight."
#                           TRUE of some of their emit sites and false of
#                           others -- see AMBIGUOUS_ISSUANCE below, which is
#                           where the measurements are and which is why
#                           row_for() will not answer for either of these
#                           without being told.
#   scope_denied,           PRE-ISSUANCE refusals. Both come out of
#   rate_limited            Policy.decide, which Sender.issue calls BEFORE
#                           http.send -- S4's pinned decision order is
#                           not_configured -> halted -> scope_denied ->
#                           method_denied -> dangerous_denied -> rate_limited
#                           -> budget_exhausted, and every one of those is
#                           settled while the request is still in the JVM.
#                           They appear here only because exchange.outcome's
#                           vocabulary carries the same two names for the
#                           proxy and crawler, which are their own egress
#                           point and their own plan.
#
# PRECEDENCE, spelled out rather than left to be inferred: for an error class
# in BOTH maps -- exactly PRE_ISSUANCE below -- **DENIAL_KIND wins**. A
# refusal decided before issuance is a `denial` row. Routing one through this
# map instead writes a `via='send'` exchange row for a request that was never
# sent, which over-counts `requests_issued` and every coverage number derived
# from it -- a report claiming reach the run never had.
#
# `transport_error` is deliberately absent: exchange.outcome offers
# conn_refused, dns_error and tls_error, and the extension reports one class
# for all three because Montoya's reply does not distinguish them. Recording a
# guess as one of the three would put a fabricated fact in the evidence store.
EXCHANGE_OUTCOME: dict[str, str] = {
    "timeout": "timeout",
    "bridge_lost": "bridge_lost",
    "rate_limited": "rate_limited",
    "scope_denied": "scope_denied",
}

# The error classes both maps name, and the answer to "which map owns this
# one". Both are refused before the request leaves the JVM, so both are
# denials; see the precedence note above. A test pins this against the real
# intersection, so a third class landing in both cannot do it silently.
PRE_ISSUANCE = frozenset({"scope_denied", "rate_limited"})

# Error classes whose ONE name covers a request that left the JVM and a
# request that never did. Nothing on the `error` frame separates them -- it
# carries `{id, class, detail}` and nothing else -- so this module refuses to
# route them from the class alone. See row_for().
#
# MEASURED, driving the real Sender with an Http that counts its calls:
#
#   E1  past-deadline AND out-of-scope   ->  class=timeout  http.calls=0
#       detail: deadline passed 1000us before this frame was decided;
#               not issued
#   E2  deadline expired MID-FLIGHT      ->  class=timeout  http.calls=1
#       detail: response arrived 1000us after the deadline
#
# E1 is step 1 of `Sender.decideAndIssue`'s ORDER OF REFUSAL -- ahead of the
# Gate and ahead of scope, behind only the frame-readability checks: the caller has already given up, and spending a rate token and a
# budget slot on a request nothing is waiting for shortens the run for no
# evidence. So it refuses before the JVM has done anything at all -- the same
# family as `not_configured`, and an exchange row for it is a request the
# report would claim was sent.
#
# `bridge_lost` straddles on the Python side and in three directions:
#
#   server._send, self._conn is None   nothing was written; there is no socket
#                                      to have written to. VERIFIED: raises
#                                      BridgeError(class='bridge_lost') with
#                                      zero bytes on any wire.
#   server._send, sendall() raised     a partial write is possible, so this
#                                      one is genuinely unknown.
#   the outstanding-send sweep on      the frame WAS written and the peer went
#   disconnect                         away holding it.
#
# The harm is one-directional, which is why the refusal is worth its awkward
# call site: filing a never-issued request as an exchange inflates
# requests_issued and every coverage number derived from it, and a report
# claiming reach the run never had is the failure this store exists to avoid.
AMBIGUOUS_ISSUANCE = frozenset({"timeout", "bridge_lost"})
# The exchange table's own vocabulary, which is wider than the map above: most
# of these describe a request that SUCCEEDED, or failed in a way no error
# class names. `status_unreadable` is one of those -- it arrives on a `result`
# frame, not an `error` frame, and it means the exchange completed while its
# final status could not be read: the transport reported an interim 1xx head
# and no final status line was found behind it, whether because the peer sent
# more interim heads than the extension's scan tolerates or because the
# response was truncated after one. `status` holds the conservative sentinel
# 599 either way.
#
# The wire value and the column value are DELIBERATELY the same string, so
# there is no map here to keep in step -- see the spec's S5/S6 amendment of
# 2026-08-23. A test drives every value below through a real INSERT, because
# this list agreeing with schema.sql is the whole of its usefulness.
EXCHANGE_OUTCOMES = frozenset({
    "ok", "timeout", "conn_refused", "dns_error", "tls_error",
    "scope_denied", "rate_limited", "bridge_lost", "truncated",
    "status_unreadable",
})

# The status that MUST accompany outcome='status_unreadable', and the only one.
# S5: `status` holds the conservative sentinel 599 "so S4's auto-halt counts it
# as an error rather than a healthy sample", and `outcome` is the only thing
# separating that sentinel from a peer that genuinely answered 599. The two
# travel together or the pair means nothing: an unreadable status filed as 200
# is a healthy sample fed to the auto-halt, and a 599 with no outcome beside it
# is a fabricated server error.
#
# The extension already pairs them by construction (Sender.STATUS_UNREADABLE),
# but record_exchange is the SINGLE place the pairing reaches disk, so it is
# the only place that can refuse a caller who breaks it.
STATUS_UNREADABLE = 599

# Outcomes that mean nothing on the far side ever answered with a status.
# S5: "a transport failure has no HTTP status". A row carrying one anyway
# reads as evidence of a response nobody received, and a check reads that row
# later without ever seeing the frame it came from.
#
# `scope_denied` and `rate_limited` are statusless too and are deliberately
# NOT here: they are decided BEFORE issuance, so the honest row for either is
# a `denial`, not an exchange at all -- see EXCHANGE_OUTCOME above. Listing
# them here would put this module's weight behind the wrong table.
NO_STATUS_OUTCOMES = frozenset({"timeout", "conn_refused", "dns_error",
                                "tls_error", "bridge_lost"})

# S5's `via` vocabulary, and the schema's CHECK enforces the same three.
# `send` was the only value either writer could produce until Plan 4:
# record_exchange hardcoded the literal and `denial` had no column to put one
# in. `proxy` and `crawl` are the two other egress points, and a fourth value
# would mean a fourth path -- which S4 forbids outright.
#
# Both `exchange.via` and `denial.via` carry it, and a test compares this
# constant against BOTH constraints rather than one: the column was added to
# `denial` in Plan 4 and two CHECKs spelling the same vocabulary are two
# places for it to drift.
VIA_VALUES = frozenset({"proxy", "send", "crawl"})

# Error classes with no row of their own, named rather than forgotten.
# `denial.kind` and `exchange.outcome` are CHECK-constrained vocabularies
# written before these classes existed, and widening either is a schema
# migration -- a new SCHEMA_VERSION and a table rebuild. A class in here still
# reaches the caller as BridgeError.error_class; what it does not get is a row.
#
# WHAT IS LEFT HERE IS NOT A DENIAL, and that is the whole of why the set is
# allowed to be non-empty. S4's sentence -- "Any denial produces a `denial` row
# and a distinct error class. Denials are never silent" -- is about DENIALS,
# and every remaining member is a transport failure, a run-wide stop, or a
# refusal about a FRAME rather than about a request the extension agreed to
# look at. `unmanaged_credential` was the one exception, which is exactly why
# it was called "the gap to close first"; it left this set on 2026-08-25 for
# DENIAL_KIND and a `credential` row. What is left is a category rather than a
# backlog, and the rule that follows from it is the useful part: a new class
# that IS a denial must be given a `kind` rather than added below.
#
#   transport_error -- the request DID leave the JVM, so it belongs in
#       `exchange`, but see EXCHANGE_OUTCOME above.
#   halted -- not a per-request denial at all. One distressed host aborts the
#       whole run, which is `run.status = 'aborted'` with a `stop_reason`;
#       abort_run() writes it.
#   bad_frame -- the extension could not read the frame: a send with no
#       deadline_us, or a body that will not parse as an HTTP request. There
#       is no method and no url it ever agreed to look at, so a `denial` row
#       would have nothing true to put in those columns. This one is a harness
#       bug, not a policy decision.
#   engagement_mismatch -- the frame named an engagement this extension does
#       not serve, so THIS store is not the one the refusal belongs in.
#       Writing the row here would file one client's traffic against another,
#       which is the exact failure the id on the frame exists to prevent.
#   protocol_mismatch -- the peer speaks a different protocol version.
#       BridgeClient.handle() checks `v` before it switches on `t`, so this
#       can answer a send; it is a refusal about the FRAME, like bad_frame,
#       and it drops the channel to DENY-ALL as well. Nothing about a request
#       was decided.
#   bad_config -- a configure whose body would not parse. Named for the same
#       reason as the two above even though its only emitter today is
#       handle()'s `configure` arm: it is in S6's class list, and a class that
#       gains a second emitter later must not be able to do so silently.
#   unknown_frame -- the frame's `t` is not a type this version knows. Exactly
#       bad_frame's shape: one frame refused, the channel kept, and nothing
#       about a request decided. It was in NONE of these three sets until the
#       2026-08-23 amendment, so `test_every_error_class_has_somewhere_to_go`
#       passed while an emittable class had nowhere to go -- the set was
#       transcribed from S6 by hand and S6 did not list it either. Both ends
#       of that are fixed: S6 lists it, and the set is now DERIVED from the
#       emit sites.
UNRECORDABLE = frozenset({"transport_error", "halted",
                          "bad_frame", "engagement_mismatch",
                          "protocol_mismatch", "bad_config", "unknown_frame"})


def row_for(error_class: str, *,
            issued: bool | None = None) -> tuple[str, str] | None:
    """Where one `error` frame's row goes, or None when it goes nowhere.

    Returns ``("denial", kind)`` or ``("exchange", outcome)`` -- the value
    ready for `record_denial(kind=...)` or `record_exchange(outcome=...)`.

    THIS IS THE SUPPORTED WAY IN. Reading DENIAL_KIND or EXCHANGE_OUTCOME
    directly gets the precedence wrong for the two classes in both, and gets
    ISSUANCE wrong for the two in AMBIGUOUS_ISSUANCE -- and both mistakes fail
    in the same direction, an exchange row for a request that was never sent.

    `issued` says whether the request reached the wire. It is REQUIRED for a
    class in AMBIGUOUS_ISSUANCE and ignored for every other, because for every
    other the class already answers it. Raising rather than defaulting is the
    point: a default here is this module guessing on the caller's behalf, and
    the guess that inflates `requests_issued` is the one a caller who had not
    thought about it would get.

    An `issued=False` ambiguous class routes NOWHERE. `denial.kind`'s
    vocabulary is Plan 1's and has no value for "the caller's deadline had
    already passed", so the honest answer today is no row rather than a row
    filed under a reason that is not the reason. This was the same position
    `unmanaged_credential` was in until SCHEMA_VERSION 6 gave it a kind; the
    difference is that a never-issued `timeout` is not a DENIAL -- nobody
    refused it, the caller gave up -- so S4's "denials are never silent" does
    not reach it, and a kind of its own would be a new fact rather than a
    vocabulary this store already had.
    """
    if error_class in DENIAL_KIND:
        # Precedence, and it is the whole reason this is a function: the two
        # classes in PRE_ISSUANCE are in both maps.
        return ("denial", DENIAL_KIND[error_class])
    if error_class in AMBIGUOUS_ISSUANCE:
        if issued is None:
            raise ValueError(
                f"{error_class!r} names both a request that left the JVM and "
                "one that never did, so it cannot be routed from the class "
                "alone; pass issued=True/False. See "
                "records.AMBIGUOUS_ISSUANCE for the measured emit sites."
            )
        return ("exchange", EXCHANGE_OUTCOME[error_class]) if issued else None
    if error_class in EXCHANGE_OUTCOME:
        return ("exchange", EXCHANGE_OUTCOME[error_class])
    if error_class in UNRECORDABLE:
        return None
    raise ValueError(
        f"{error_class!r} is not an error class this module knows where to "
        "put. Every class spec S6 lists is named by at least one of "
        "DENIAL_KIND, EXCHANGE_OUTCOME and UNRECORDABLE -- two of them by "
        "both of the first two, which is what the precedence note above is "
        "for -- and a new one has to be decided about here rather than "
        "discarded."
    )


def new_id(prefix: str) -> str:
    """`<prefix>-<12 hex>`, the id shape every table in this store uses.

    `hx.engagement._new_id` is this function's twin and produces the same
    shape. They are not one function yet -- engagement.py is Plan 1's and
    collapsing them is a refactor with its own test surface -- so a test pins
    the shape of both rather than letting them drift apart unnoticed.
    """
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def record_denial(conn: sqlite3.Connection, *, run_id: str | None, kind: str,
                  method: str, url: str, detail: str, at_us: int,
                  via: str = "send", resolved_ip: str | None = None,
                  scope_version_id: str | None = None) -> str:
    """Record one refused request. Returns the row id.

    `kind` is a schema value, not an error class: map it through DENIAL_KIND.
    The check below is redundant with the table's CHECK constraint and exists
    for the message -- SQLite answers a bad kind with "CHECK constraint
    failed: denial", which names neither the value nor the vocabulary.

    `run_id` may be None. A `not_configured` denial at 02:00 happens before
    any run row exists, and that denial is exactly the one worth having.

    `via` says WHICH EGRESS POINT refused. It defaults to 'send' because these
    writers were built for the send path and every call site that predates
    Plan 4 is one of its rows -- a default that is a fact about this module's
    history, not a guess about the caller. `hx.capture` passes 'proxy'.
    """
    if via not in VIA_VALUES:
        raise ValueError(f"unknown via {via!r}; S5 names {sorted(VIA_VALUES)}")
    if kind not in DENIAL_KINDS:
        raise ValueError(
            f"{kind!r} is not a denial kind; the schema accepts "
            f"{sorted(DENIAL_KINDS)}. Map an error class through "
            "records.DENIAL_KIND, and see records.UNRECORDABLE for the "
            "classes that have no row to go in yet."
        )
    # AT THE WRITER, not at the caller, and for `count_drop`'s reason: this is
    # where a url becomes a row, so it covers the callers that do not exist
    # yet. `hx.capture` is the only one today and it hands the raw frame value
    # straight through.
    url = redact_url(url)
    row_id = new_id("d")
    conn.execute(
        "INSERT INTO denial(id, run_id, ts_us, kind, method, url, resolved_ip,"
        " reason, via, scope_version_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (row_id, run_id, at_us, kind, method, url, resolved_ip, detail, via,
         scope_version_id),
    )
    return row_id


def record_exchange(conn: sqlite3.Connection, *, run_id: str | None,
                    method: str, url: str, status: int | None,
                    req_blob: str | None, resp_blob: str | None, ms: int,
                    at_us: int, outcome: str = "ok", via: str = "send",
                    resp_len: int | None = None,
                    surface_id: str | None = None,
                    scope_version_id: str | None = None,
                    seq: int | None = None) -> str:
    """Record one request that was issued. Returns the row id.

    `req_blob` and `resp_blob` are blob-store digests of the REDACTED bytes.
    Redaction happens inside the JVM, before these ever reach Python (S7): the
    blob store is content-addressed, so hashing raw bytes and redacting
    afterwards means the raw bytes are already on disk.

    `outcome` and `status` come off a `result` frame unchanged in VALUE, but
    they are not taken on trust: the two are one fact, and the three guards
    below refuse every way of writing them so they disagree. In particular
    `outcome='status_unreadable'` with `status=599` is a completed exchange
    whose final status could not be read, NOT a peer that answered 599 -- and
    the two are indistinguishable by status alone, which is why the frame
    carries the outcome at all. That pairing reaches disk HERE and nowhere
    else, so this is the only place it can be enforced.

    `via` was always 'send' here until Plan 4, when `hx.capture` became the
    proxy's egress point and passed 'proxy'. It still DEFAULTS to 'send', so
    every send-path call site is unchanged; `crawl` has no caller yet.

    `identity`, `identity_generation` and `identity_state` stay NULL. Identity
    injection ships in Plan 5; writing 'assumed' now would be a claim about
    authentication that nothing in this plan can support.
    """
    if via not in VIA_VALUES:
        raise ValueError(f"unknown via {via!r}; S5 names {sorted(VIA_VALUES)}")
    if outcome not in EXCHANGE_OUTCOMES:
        raise ValueError(
            f"{outcome!r} is not an exchange outcome; the schema accepts "
            f"{sorted(EXCHANGE_OUTCOMES)}. Map an error class through "
            "records.EXCHANGE_OUTCOME."
        )
    if status is None and outcome in ("ok", "truncated"):
        # Both mean a response CAME BACK -- 'ok' whole, 'truncated' cut short
        # -- so a row claiming one with no status is a row that reads as
        # evidence and is not.
        #
        # 'truncated' was outside this guard until 2026-08-25, and the guard's
        # absence was reachable: a `result` frame with no `status` key at all
        # reached `hx.capture` and MEASURED an accepted exchange, one surface,
        # `requests_issued=1` and `status NULL`. The third outcome that means
        # a response came back, 'status_unreadable', is refused by the
        # stricter guard below -- its only legal status is the 599 sentinel,
        # so None fails there.
        #
        # What is left may be NULL and the NULL is the fact: NO_STATUS_OUTCOMES
        # never had a status to carry, and scope_denied/rate_limited were
        # decided before issuance. A test drives this off the same table that
        # says which status each outcome may legally carry.
        raise ValueError(
            f"an exchange with outcome={outcome!r} and no status is not an "
            "exchange that happened; give it the outcome it really had")
    if outcome == "status_unreadable" and status != STATUS_UNREADABLE:
        # The converse of the guard above, and the one this task was the
        # deliberate verification for. See STATUS_UNREADABLE.
        raise ValueError(
            f"outcome='status_unreadable' with status={status!r}: the two are "
            f"one fact and must travel together. `status` holds "
            f"{STATUS_UNREADABLE} so S4's auto-halt counts an unreadable "
            "status as an error rather than a healthy sample, and `outcome` "
            f"is the only thing separating that sentinel from a peer that "
            f"genuinely answered {STATUS_UNREADABLE}."
        )
    if outcome in NO_STATUS_OUTCOMES and status is not None:
        raise ValueError(
            f"outcome={outcome!r} has no HTTP status, and this row claims "
            f"{status!r}. S5: a transport failure has no HTTP status -- a row "
            "saying both that the transport failed and that the peer answered "
            "is not a fact about anything, and a check reads it later without "
            "the frame it came from."
        )
    # §7, the same call `record_denial` makes and for the same reason: the two
    # url columns are one exposure and a rule applied to one of them is a rule
    # the other drifts away from.
    url = redact_url(url)
    row_id = new_id("x")
    conn.execute(
        "INSERT INTO exchange(id, run_id, surface_id, via, outcome, sent_us,"
        " recv_us, method, url, status, req_blob, resp_blob, resp_len,"
        " body_shed, scope_version_id, seq)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (row_id, run_id, surface_id, via, outcome, at_us,
         at_us + ms * 1000, method, url, status, req_blob, resp_blob,
         resp_len,
         # S6: solicited exchanges are NEVER shed -- they are about to become
         # evidence. Only unsolicited proxy observations may set this.
         0,
         scope_version_id, seq),
    )
    return row_id


def abort_run(conn: sqlite3.Connection, *, run_id: str,
              stop_reason: str, at_us: int) -> bool:
    """Stop a run. True if this call stopped it, False if it was already over.

    S4: "One distressed host aborts the whole run" -- `run.status = aborted`
    with a `stop_reason`, not just that host -- so this is a single update on
    the run rather than a per-host mark.

    The UPDATE is guarded on `status='running'`, which makes the writer both
    idempotent and order-independent: the FIRST stop_reason wins, and it is
    the one that explains what happened. A second `halted` frame from another
    host arriving while the first is still being written, or an operator halt
    racing the same stop, must not replace the diagnosis with a symptom.

    Returning False rather than raising is deliberate. This is called from the
    bridge's `halted` handler, and two distressed hosts inside one window is a
    perfectly ordinary thing for a struggling target to do. An unknown
    run_id raises rather than returning False; see the comment below.
    """
    cur = conn.execute(
        "UPDATE run SET status='aborted', stop_reason=?, ended_us=?"
        " WHERE id=? AND status='running'",
        (stop_reason, at_us, run_id),
    )
    if cur.rowcount == 1:
        return True
    if conn.execute("SELECT id FROM run WHERE id=?", (run_id,)).fetchone() is None:
        # Not "already stopped" -- this store has never heard of the run. The
        # caller is holding an id from somewhere else, and silently doing
        # nothing would leave a live run marked as running forever.
        raise ValueError(f"no run {run_id!r} in this store")
    return False


def dedupe_key(*, type_: str, scheme: str, host: str, port: int | None,
               method: str, path_template: str,
               insertion_kind: str | None, insertion_name: str | None) -> str:
    """`type|scheme|host|port|method|path_template|insertion_kind|insertion_name`.

    LITERAL `-` FOR ABSENT PARTS, NEVER `None`. `finding.dedupe_key` is
    `TEXT NOT NULL`, so this function must never itself hand back a bare
    `None` -- verified: `INSERT INTO finding(...) VALUES(..., NULL, ...)`
    raises `IntegrityError: NOT NULL constraint failed: finding.dedupe_key`
    rather than inserting. That is the good case. The bad case this rule
    actually guards against is the one where a part is missing and the
    string built from it is well-formed anyway: SQLite's rule for a UNIQUE
    index is that two NULLs are never equal, not even to each other, so any
    design that let an absent part reach SQL as a real NULL -- a raw column
    in a composite UNIQUE, or a key built by SQL `||` concatenation, where
    `NULL || anything` is itself `NULL` -- would let the same finding insert
    again on every scan, silently, with the constraint sitting there looking
    like it worked. Collapsing every part into ONE Python string with a
    literal placeholder for an absent part is what keeps that failure mode
    out of reach in the first place, by never handing SQL a NULL to be
    careless with.

    Method and insertion kind are part of identity because S5 says they are:
    `GET /api/order/{n}` leaking another tenant's data and `POST` on the same
    template accepting mass-assignment are different findings with different
    remediations.
    """
    parts = (type_, scheme, host, port, method, path_template,
             insertion_kind, insertion_name)
    return "|".join("-" if p is None or p == "" else str(p) for p in parts)


def upsert_finding(conn: sqlite3.Connection, *, engagement_id: str, candidate,
                   dedupe_key: str, run_id: str, surface_id: str | None = None,
                   host: str | None = None) -> str:
    """Insert the finding, or move `last_seen_run` if it is already known.

    WHAT AN UPSERT MUST NOT TOUCH: `status`, and `first_seen_run`. An operator
    who marked something `false_positive` has made a judgement the next scan
    has no standing to reverse, and the run something was FIRST seen in is a
    historical fact. The DO UPDATE clause names exactly what moves.

    `surface_id` AND `host` ARE KEYWORD-ONLY AND DEFAULT TO `None` --
    BACKWARD COMPATIBLE with every call site that predates Task 6, which
    is every test in `tests/test_records_findings.py`. They exist because
    `hx.scan._mark_unobserved` reads them back: `finding.surface_id IN
    (<tested ids>)` is how a retest tells "this finding's surface was
    looked at again and it was clean" from "nobody looked". Before this
    parameter existed, `upsert_finding` never wrote `surface_id` at all --
    the column stayed NULL forever, no writer set it, and `IN (...)` against
    an all-NULL column matches ZERO rows. MEASURED: driving `hx.scan.run`
    twice over one surface, once finding and once clean, through the literal
    task-6-brief `upsert_finding` call with no `surface_id` argument produced
    `finding_observation.observed == [1]`, one row, never `[1, 0]` -- the
    retest half of S12 silently did nothing, on every finding, forever. The
    fix is here rather than in the runner because `dedupe_key` is already
    built from surface identity in exactly one place (this module's
    `dedupe_key`) and a second place deciding `surface_id` would be the same
    class of drift that function's docstring warns about.
    """
    fid = new_id("f")
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, description,"
        " impact, remediation, cwe, severity, confidence, created_by, status,"
        " insertion_name, insertion_kind, scope_level, payload, surface_id,"
        " host, first_seen_run, last_seen_run)"
        " VALUES(?,?,?,?,?,?,?,?,?,?, 'check', 'new', ?,?,?,?,?,?,?,?)"
        " ON CONFLICT(engagement_id, dedupe_key) DO UPDATE SET"
        "   last_seen_run=excluded.last_seen_run,"
        "   severity=excluded.severity,"
        "   confidence=excluded.confidence,"
        "   surface_id=excluded.surface_id,"
        "   host=excluded.host",
        (fid, engagement_id, dedupe_key, candidate.title, candidate.description,
         candidate.impact, candidate.remediation, candidate.cwe,
         candidate.severity, candidate.confidence,
         candidate.insertion.name if candidate.insertion else None,
         candidate.insertion.kind if candidate.insertion else None,
         candidate.scope_level, candidate.payload, surface_id, host,
         run_id, run_id))
    row = conn.execute(
        "SELECT id FROM finding WHERE engagement_id=? AND dedupe_key=?",
        (engagement_id, dedupe_key)).fetchone()
    return row[0]


def record_observation(conn: sqlite3.Connection, *, finding_id: str,
                       run_id: str, observed: bool,
                       exchange_id: str | None, severity_at: str | None,
                       confidence_at: str | None, at_us: int) -> None:
    """This run's answer about this finding.

    `observed=0` is how a retest says FIXED -- but only where the surface was
    actually tested. The caller owns that distinction; see `hx.scan`.

    A SECOND CALL FOR THE SAME `(finding_id, run_id)` REPLACES THE WHOLE ROW,
    not a subset of its columns. F7 of the task-5 review: the DO UPDATE used
    to refresh `observed`, `exchange_id` and `ts_us` but leave `severity_at`
    and `confidence_at` at whatever the FIRST call in this run wrote, so two
    calls in one run could leave a row pairing a stale severity with a fresh
    `observed` -- one row claiming to be "this run's answer" while two of its
    five fields answered for different moments. This row is not a
    point-in-time record with its own history; that history is `run_id`
    itself, one row per run. Within one run there is exactly one current
    answer, and the last call to name it wins on every column.
    """
    conn.execute(
        "INSERT INTO finding_observation(finding_id, run_id, observed,"
        " exchange_id, severity_at, confidence_at, ts_us)"
        " VALUES(?,?,?,?,?,?,?)"
        " ON CONFLICT(finding_id, run_id) DO UPDATE SET"
        "   observed=excluded.observed, exchange_id=excluded.exchange_id,"
        "   severity_at=excluded.severity_at,"
        "   confidence_at=excluded.confidence_at,"
        "   ts_us=excluded.ts_us",
        (finding_id, run_id, 1 if observed else 0, exchange_id,
         severity_at, confidence_at, at_us))


def record_evidence(conn: sqlite3.Connection, *, finding_id: str,
                    exchange_ids, at_us: int) -> None:
    """Append the given exchanges to this finding's evidence chain, `seq`
    continuing from what is already there. `seq` is the order S12 renders
    the chain in.

    `evidence` is append-only BY SCHEMA: `trg_evidence_no_update` and
    `trg_evidence_no_delete` both `RAISE(ABORT, 'evidence is immutable')`,
    because evidence is what a disputed finding is proven with and must not
    be alterable after capture. The plan originally specified this function
    as REPLACE -- `DELETE FROM evidence` then re-insert -- and that raised
    `IntegrityError` on the second recording of any finding, measured, which
    is how the trigger was found. This function only ever appends.

    THE SKIP BELOW DOES ONE THING: it records each EXCHANGE ID once per
    finding, so calling this twice with the same ids -- a retry, a duplicate
    dispatch inside one run -- does not double the chain. F1 of the task-5
    review: an earlier version of this docstring claimed that property as "a
    chain that does not grow on re-observation" and "a finding seen in three
    runs would not carry its exchange three times". That is FALSE of the real
    path. `record_exchange` mints a fresh `x-<random>` id per row
    (`new_id("x")`), so a later run observing the same finding produces a
    NEW exchange with a new id every time -- the skip never fires across
    runs, and a finding seen in N runs genuinely accumulates N evidence rows,
    one per observation. This function does not and cannot dedupe across
    runs; it has no stable key to dedupe on that would not also be a claim
    about identity this module does not own. Per-run persistence -- "how many
    runs has this been seen in" -- is `finding_observation`'s job, whose
    primary key is `(finding_id, run_id)`; that is the table that answers it,
    not this one.

    UNBOUNDED GROWTH IS THE REAL CONSEQUENCE AND IS NOT FIXED HERE: a finding
    seen in fifty runs holds fifty evidence rows, and a report must not print
    fifty rows for one problem. §12 renders this chain; bounding what it
    shows is the renderer's job, not this writer's -- the reader's next
    question, named rather than solved.

    Wrapped in `db.transaction` (F5 of the task-5 review): on the autocommit
    connection `db.connect()` returns, an unwrapped multi-row loop failing
    partway through leaves the rows already inserted committed -- a partial
    chain that looks like the whole one until someone counts it.
    """
    with transaction(conn):
        known = {row[0] for row in conn.execute(
            "SELECT exchange_id FROM evidence WHERE finding_id=?",
            (finding_id,))}
        seq = conn.execute(
            "SELECT COALESCE(MAX(seq) + 1, 0) FROM evidence WHERE finding_id=?",
            (finding_id,)).fetchone()[0]
        for exchange_id in exchange_ids:
            if exchange_id in known:
                continue
            conn.execute(
                "INSERT INTO evidence(id, finding_id, seq, role, kind,"
                " exchange_id, captured_us) VALUES(?,?,?,'proof','exchange',?,?)",
                (new_id("ev"), finding_id, seq, exchange_id, at_us))
            known.add(exchange_id)
            seq += 1
