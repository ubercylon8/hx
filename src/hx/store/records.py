"""What the send path did: denial rows and exchange rows.

The extension has no database access by design -- the jar's dependency list is
deliberately empty and nothing inside Burp's JVM should be able to write the
evidence store -- so every row the send path produces is written from here.
Spec S4: "Any denial produces a `denial` row and a distinct error class.
Denials are never silent."

Both writers are keyword-only. Between them the two tables take twenty-one
columns, six of which are nullable ids of the same shape, and a positional
call site that drifted by one argument would file evidence against the wrong
run without any type error to show for it.

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

# Error class -> the `outcome` the exchange table accepts, for a request that
# reached the far side of the bridge and then failed. `transport_error` is
# deliberately absent: exchange.outcome offers conn_refused, dns_error and
# tls_error, and the extension reports one class for all three because
# Montoya's reply does not distinguish them. Recording a guess as one of the
# three would put a fabricated fact in the evidence store.
EXCHANGE_OUTCOME: dict[str, str] = {
    "timeout": "timeout",
    "bridge_lost": "bridge_lost",
    "rate_limited": "rate_limited",
    "scope_denied": "scope_denied",
}
# The exchange table's own vocabulary, which is wider than the map above: most
# of these describe a request that SUCCEEDED, or failed in a way no error
# class names. `status_unreadable` is one of those -- it arrives on a `result`
# frame, not an `error` frame, and it means the exchange completed while its
# final status could not be read (more interim 1xx heads than the extension's
# scan tolerates), with `status` holding the conservative sentinel 599.
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
UNRECORDABLE = frozenset({"unmanaged_credential", "transport_error", "halted",
                          "bad_frame", "engagement_mismatch",
                          "protocol_mismatch", "bad_config"})


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
