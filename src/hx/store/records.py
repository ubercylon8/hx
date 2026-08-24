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
**25** columns -- 9 on `denial`, 16 on `exchange` -- not twenty-one; 21 is the
number of KEYWORD PARAMETERS the two writers take between them (8 and 13),
which is a different thing and the likely source of the error. And **five** of
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
"""
from __future__ import annotations

import sqlite3
import uuid

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
}
DENIAL_KINDS = frozenset(DENIAL_KIND.values())

# The prefix a `not_configured` detail carries when the EXTENSION is at fault
# rather than the operator.
#
# `not_configured` is overloaded -- S6 and docs/bridge-protocol.md both record
# it -- and the two readings are opposite instructions: "an operator has not
# authorised this run yet" and "this jar is broken". Both map to
# kind='not_configured' above, so without this
#
#     SELECT kind, COUNT(*) FROM denial GROUP BY kind
#
# reads a crashed send path as an unauthorised run. Splitting the CLASS needs
# an S6 amendment; the detail carries it today, and a prefix carries it in a
# form a consumer can test for. `BridgeClient.EXTENSION_FAULT` is the same
# string on the Java side, and a test pins the pair.
EXTENSION_FAULT = "extension fault: "

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
# E1 is `Sender.decideAndIssue`'s FIRST check, ahead of the Gate and ahead of
# scope: the caller has already given up, and spending a rate token and a
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

# Error classes with no row of their own, named rather than forgotten.
# `denial.kind` and `exchange.outcome` are CHECK-constrained vocabularies
# written before these classes existed, and widening either is a schema
# migration -- a new SCHEMA_VERSION and a table rebuild. A class in here still
# reaches the caller as BridgeError.error_class; what it does not get is a row.
#
#   unmanaged_credential -- a real denial (S7 refuses the request and never
#       persists it) with no `kind` to record it under. This is the gap to
#       close first: it is the only class here that S4 calls a denial about a
#       request the extension agreed to look at.
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
UNRECORDABLE = frozenset({"unmanaged_credential", "transport_error", "halted",
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
    filed under a reason that is not the reason -- the same position
    `unmanaged_credential` is in, and it belongs in the same schema migration.
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
                  resolved_ip: str | None = None,
                  scope_version_id: str | None = None) -> str:
    """Record one refused request. Returns the row id.

    `kind` is a schema value, not an error class: map it through DENIAL_KIND.
    The check below is redundant with the table's CHECK constraint and exists
    for the message -- SQLite answers a bad kind with "CHECK constraint
    failed: denial", which names neither the value nor the vocabulary.

    `run_id` may be None. A `not_configured` denial at 02:00 happens before
    any run row exists, and that denial is exactly the one worth having.
    """
    if kind not in DENIAL_KINDS:
        raise ValueError(
            f"{kind!r} is not a denial kind; the schema accepts "
            f"{sorted(DENIAL_KINDS)}. Map an error class through "
            "records.DENIAL_KIND, and see records.UNRECORDABLE for the "
            "classes that have no row to go in yet."
        )
    row_id = new_id("d")
    conn.execute(
        "INSERT INTO denial(id, run_id, ts_us, kind, method, url, resolved_ip,"
        " reason, scope_version_id) VALUES(?,?,?,?,?,?,?,?,?)",
        (row_id, run_id, at_us, kind, method, url, resolved_ip, detail,
         scope_version_id),
    )
    return row_id


def record_exchange(conn: sqlite3.Connection, *, run_id: str | None,
                    method: str, url: str, status: int | None,
                    req_blob: str | None, resp_blob: str | None, ms: int,
                    at_us: int, outcome: str = "ok",
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

    `via` is always 'send' here. The other two values in that vocabulary
    belong to the proxy and the crawler, which are their own egress point and
    their own plan.

    `identity`, `identity_generation` and `identity_state` stay NULL. Identity
    injection ships in Plan 5; writing 'assumed' now would be a claim about
    authentication that nothing in this plan can support.
    """
    if outcome not in EXCHANGE_OUTCOMES:
        raise ValueError(
            f"{outcome!r} is not an exchange outcome; the schema accepts "
            f"{sorted(EXCHANGE_OUTCOMES)}. Map an error class through "
            "records.EXCHANGE_OUTCOME."
        )
    if outcome == "ok" and status is None:
        # 'ok' means a response came back. A row claiming one with no status
        # is a row that reads as evidence and is not.
        raise ValueError("an 'ok' exchange with no status is not an exchange "
                         "that happened; give it the outcome it really had")
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
    row_id = new_id("x")
    conn.execute(
        "INSERT INTO exchange(id, run_id, surface_id, via, outcome, sent_us,"
        " recv_us, method, url, status, req_blob, resp_blob, resp_len,"
        " body_shed, scope_version_id, seq)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (row_id, run_id, surface_id, "send", outcome, at_us,
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
