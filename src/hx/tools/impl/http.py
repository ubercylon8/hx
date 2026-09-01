# src/hx/tools/impl/http.py
"""The four ways an agent touches the wire and what it got back.

PRINCIPLE 1 IS THE SHAPE OF THIS MODULE: handles and digests, never payloads.
`send` and `replay_as` return a digest; `grep` and `body` are how the bytes
behind a digest are read, and they are separate tools precisely so that
reading is a decision an agent makes and a journal records, rather than
something that happens to every response whether or not anyone wanted it.

PRINCIPLE 2 IS WHY `grep` COMES BEFORE `body`. An agent does not know where in
a 1.2 MB bundle the interesting bytes are, so match-addressed reading is the
documented default and `body(range)` is the escape hatch used AFTER a match
yields an offset.

PRINCIPLE 6 IS WHY ALMOST NOTHING HERE DECIDES ANYTHING. Scope, method,
dangerous paths, rate and budget are the extension's, and this module's whole
job on a refusal is to report the class the wire answered with. A refusal
translated into `error / internal` would tell an agent hx is broken at the
exact moment hx worked as designed.
"""
from __future__ import annotations

from ... import config as config_mod
from ... import delta as delta_mod
from ... import http_text
from ... import identity as identity_mod
from ... import issue as issue_mod
from ...bridge.server import BridgeError
from ...store.blobs import CorruptBlob
from .. import envelope, live, registry, spec
from ..errors import ToolRefused, ToolUnavailable

#: Latin-1 everywhere bytes become text in a return value, and it is a
#: deliberate choice rather than a default. It is the only codec that maps
#: every byte to exactly one character and back, so a response no UTF-8
#: decoder could read still round-trips through a JSON envelope -- and a
#: binary body does not silently become a string of replacement characters
#: that an agent then greps for a payload it will never find.
TEXT = "latin-1"

#: The methods the tool layer will compose. Not a security control -- the
#: extension's `method.allow` is that, and it is checked again in the JVM --
#: but a list an agent can read off `tools/list` beats a 400 from a peer.
METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

#: One megabyte of request body. `hx.tools.journal` spills arguments over 4 KB
#: to the blob store, so a large body costs a blob rather than a giant
#: `agent_action` row -- this cap is about the WIRE, not the journal.
MAX_BODY = 1024 * 1024

#: The extension's error classes, placed in the envelope's closed vocabulary.
#: A class this build has never seen must NOT reach `Envelope` unmapped: the
#: constructor raises for an unknown reason, and that raise lands inside
#: `dispatch`'s `except ToolError` handler where the `except Exception` beside
#: it cannot catch it -- so it escapes `dispatch`, which never raises. A new
#: class from a future extension would take the call out with a traceback and
#: write no journal row, which is the one failure this layer is built to make
#: impossible. The fallback keeps the raw class in `detail`, so nothing is
#: lost and nothing crashes.
#:
#: RULING 19 -- ALL TWENTY, NOT ELEVEN. `UNKNOWN_CLASS` is for a class this
#: build has NEVER SEEN, and it was catching nine this build's own suite
#: enumerates: `tests/test_records.py` derives the authoritative list from the
#: Java emit sites, and three of the nine are ordinary policy denials an agent
#: reaches straight off these tools -- `unmanaged_credential` on any
#: `http.send` whose `headers` carry a Cookie or an Authorization,
#: `unknown_identity` and `identity_origin` on a send bound to an identity the
#: extension will not use for that host. Answering `unavailable /
#: transport_error` for those counted a policy denial as network weather,
#: which is the whole subject of Ruling 3.
#:
#: THE SPLIT IS RULING 3's, UNCHANGED. Something DECIDED NO is `refused`; NO
#: ANSWER CAME BACK is `unavailable`. Every frame-level refusal below got an
#: answer -- the extension read the frame and said no, exactly as it does for
#: `bad_frame`, which was already on that side -- so a stale identity
#: generation, a mismatched engagement and an unparseable configure are all
#: decisions. Only the four that decided NOTHING, plus `identity_dead`, are
#: `unavailable`.
REASON_FOR_CLASS = {
    # The Gate and the limits: policy answering, which is what a client-facing
    # refusal count is a statement about.
    "scope_denied": ("refused", "scope_denied"),
    "method_denied": ("refused", "method_denied"),
    "dangerous_denied": ("refused", "dangerous_denied"),
    "rate_limited": ("refused", "rate_limited"),
    "budget_exhausted": ("refused", "budget_exhausted"),
    "halted": ("refused", "halted"),
    # `Sender.java`'s three, and the reason Ruling 19 is not cosmetic: all
    # three are reachable from `http.send`'s own arguments. The first fires
    # BEFORE the Gate, on a request carrying a credential header the
    # extension did not itself inject; `http.send` now refuses that shape on
    # this side too (Ruling 21), so a wire answer of it means a credential
    # arrived some other way and the agent needs to hear so.
    "unmanaged_credential": ("refused", "unmanaged_credential"),
    "unknown_identity": ("refused", "unknown_identity"),
    "identity_origin": ("refused", "identity_origin"),
    # `BridgeClient.java`'s frame-level refusals. The peer read the frame and
    # said no, which is a decision however far it is from the application:
    # `bad_frame` has always been `refused` and these are its neighbours.
    "bad_frame": ("refused", "bad_frame"),
    "unknown_frame": ("refused", "unknown_frame"),
    "protocol_mismatch": ("refused", "protocol_mismatch"),
    "engagement_mismatch": ("refused", "engagement_mismatch"),
    "bad_config": ("refused", "bad_config"),
    "bad_identity": ("refused", "bad_identity"),
    "stale_generation": ("refused", "stale_generation"),
    # An identity the extension's own liveness canary has declared dead: a
    # `register_identity` refusal, not a send refusal -- the one class this
    # table maps that never comes off `issue()`. See `send`'s
    # `except BridgeError` below.
    "identity_dead": ("unavailable", "identity_dead"),
    # Nothing decided anything: no extension, no channel, no answer, no time.
    "not_configured": ("unavailable", "not_configured"),
    "bridge_lost": ("unavailable", "bridge_lost"),
    "transport_error": ("unavailable", "transport_error"),
    "timeout": ("unavailable", "timeout"),
}
UNKNOWN_CLASS = ("unavailable", "transport_error")


def _raise_for_class(reason: str, detail: str, cause: BaseException) -> None:
    """Turn a wire error class into the right `ToolError` subclass.

    SHARED by `send`'s two wire-refusal sites: `issue_mod.IssueRefused` for
    the request itself, and `BridgeError` for an identity registration the
    extension refused -- its liveness canary already having answered
    `identity_dead` for this identity, for one. Both are "the wire decided
    something", so both go through the same table.

    PRINCIPLE 6: the class is the wire's, unchanged, so an agent that gets
    `dangerous_denied` learns the profile refused it and one that gets
    `rate_limited` learns to slow down -- two different next actions that a
    single `error` would have made one. An identity refusal told as `error /
    internal` is the same defect from the other side: an agent that reads
    "hx is broken" retries the identical send forever instead of re-opening
    its session, and the report counts an instrument event -- the canary
    tripping -- as an internal defect in hx.

    A CLASS NOT IN `REASON_FOR_CLASS` falls back to `UNKNOWN_CLASS` rather
    than raising `ValueError` out of `Envelope.__post_init__` -- see this
    module's own comment on the table above. The raw class is prefixed onto
    the detail whenever the fallback fires, so an operator reading the
    journal can still see what the extension actually said even though this
    build has no name for it.
    """
    outcome, mapped = REASON_FOR_CLASS.get(reason, UNKNOWN_CLASS)
    if reason not in REASON_FOR_CLASS:
        detail = f"[unmapped class {reason!r}] {detail}".rstrip()
    cls = ToolRefused if outcome == "refused" else ToolUnavailable
    raise cls(mapped, detail) from cause


def _digest(ctx, issued) -> dict:
    """Section 8's digest for one `Issued`, including its delta.

    The bytes never appear. `issued.body` exists so this function can diff
    against the baseline's body without a round trip to the blob store
    `issue` just wrote, and it stops here.

    ONE SURFACE LOOKUP, THEN `delta.baseline_for` DOES THE REST. A first
    version of this function ran a second query here to find the surface's
    `exemplar_exchange_id` and compare it in Python against `issued.
    exchange_id`, to stop a brand-new surface's first exchange from being
    diffed against itself. `hx.issue.issue` sets that exemplar to exactly
    this exchange, inside its own transaction, before it returns -- so the
    guard is real, but the second query was a call-site workaround for
    something `baseline_for` can rule out in the query it already runs. It
    now takes `exclude_exchange_id` and does that itself.
    """
    row = ctx.conn.execute(
        "SELECT surface_id FROM exchange WHERE id=?",
        (issued.exchange_id,)).fetchone()
    base = None
    if row is not None and row[0] is not None:
        base = delta_mod.baseline_for(
            ctx.conn, ctx.blobs, row[0],
            exclude_exchange_id=issued.exchange_id)
    return {
        "exchange_id": issued.exchange_id,
        "status": issued.status,
        "bytes": issued.bytes,
        "ms": issued.ms,
        "outcome": issued.outcome,
        "content_type": issued.content_type,
        "body_sha256": issued.body_sha256,
        "first_line": issued.first_line,
        "delta_vs_baseline": (
            None if base is None
            else delta_mod.against(base[0], base[1], issued.status,
                                   issued.body)),
    }


def send(ctx, *, host: str, method: str, path: str, port: int = 80,
         scheme: str = "http", headers=None, body: str | None = None,
         identity: str | None = None) -> dict:
    """Issue one request and return its digest."""
    ident = None
    if identity is not None:
        try:
            ident = live.ensure_identity(ctx, identity)
        except ValueError as exc:
            # AN UNDECLARED IDENTITY IS THE AGENT'S MISTAKE, not a defect.
            # `bad_args` puts it beside a malformed path, which is where an
            # agent will look for it; `error / internal` would put it beside
            # a crash. Distinct from the two exceptions below: `identity:
            # "ghost"` is an argument the agent wrote and can correct.
            raise ToolRefused("bad_args", str(exc)) from exc
        except identity_mod.IdentityError as exc:
            # RULING 13. A DECLARED identity whose credential will not
            # resolve is a DIFFERENT mistake from an undeclared one:
            # `identity: "staff"` is a perfectly valid argument, and no
            # argument the agent can write fixes an operator's unset
            # `HX_STAFF_TOKEN`. `refused` would say the agent's call was
            # wrong; `unavailable` says the instrument -- the credential --
            # was not there, which is what an operator who forgot an
            # `export` needs to be told. `hx.identity`'s messages are
            # already value-free (they name the environment variable, never
            # its value), so the message is passed through rather than
            # composed anew.
            raise ToolUnavailable("identity_unresolved", str(exc)) from exc
        except BridgeError as exc:
            # The extension refused the REGISTRATION itself -- see
            # `_raise_for_class`'s docstring for why this goes through the
            # same table as a send refusal rather than becoming `error /
            # internal`.
            cls_ = exc.error_class or "transport_error"
            detail = str(exc).removeprefix(f"{cls_}: ")
            _raise_for_class(cls_, detail, exc)
    try:
        issued = issue_mod.issue(
            ctx.session.bridge, ctx.conn, ctx.blobs, ctx.config,
            engagement_id=ctx.engagement.id, run_id=ctx.run_id,
            scheme=scheme, host=host, port=port, method=method, path=path,
            headers=tuple(headers or ()),
            body=(body or "").encode(TEXT), identity=ident)
    except ValueError as exc:
        # `request_bytes` raises this for a request that could be split, and
        # the schema cannot catch it: a CR inside a string is a valid string.
        raise ToolRefused("bad_args", str(exc)) from exc
    except issue_mod.IssueRefused as exc:
        _raise_for_class(exc.reason, exc.detail or "", exc)
    return _digest(ctx, issued)


registry.register(spec.ToolSpec(
    name="http.send", handler=send, needs_egress=True, mutates=True,
    summary="Issue one HTTP request through the extension and return its "
            "digest -- never its body. Use http.grep to read what came back.",
    params={"type": "object", "additionalProperties": False,
            "required": ["host", "method", "path"], "properties": {
                "host": {"type": "string", "minLength": 1, "maxLength": 253,
                         "description": "target host; scope is enforced in "
                                        "the extension, not here"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535,
                         "description": "default 80"},
                "scheme": {"type": "string", "enum": ["http", "https"],
                           "description": "default http"},
                "method": {"type": "string", "enum": METHODS},
                "path": {"type": "string", "minLength": 1, "maxLength": 4096,
                         "description": "origin-form, starts with '/', "
                                        "percent-encoded"},
                "headers": {"type": "array", "maxItems": 64,
                            "items": {"type": "string", "maxLength": 8192},
                            "description": "wire lines, 'Name: value'. A Host "
                                           "header is added if you omit one."},
                "body": {"type": "string", "maxLength": MAX_BODY,
                         "description": "request body, latin-1"},
                "identity": {"type": "string", "maxLength": 64,
                             "description": "the NAME of an identity declared "
                                            "in config.yaml. The credential "
                                            "is resolved and injected below "
                                            "this layer; you never handle it."},
            }}))


#: `both` is the default because an agent looking for its own payload does
#: not always know which half reflected it -- a header echoed into a
#: response, a parameter echoed into the request log.
PARTS = ["request", "response", "both"]

CONTEXT_DEFAULT = 64
CONTEXT_MAX = 512
#: 64 KB per `http.body` call. Above this an agent should be grepping.
RANGE_MAX = 64 * 1024
#: Exchanges per grep. Bounded because each one is a whole body read out of
#: the blob store into memory in the one process that also holds the Burp.
MAX_EXCHANGES = 50


def _blobs_for(ctx, exchange_id, part):
    """`[(part_name, bytes)]` for one exchange, or None if it is not there.

    None covers every way there is nothing to read -- no such row, a NULL
    blob, a blob the store cannot return -- because all three are "this
    exchange cannot be searched", and a caller that told them apart would be
    reporting on hx's bookkeeping rather than on the traffic. A per-part
    `CorruptBlob` (digest mismatch, missing file) is caught here rather than
    left to propagate: uncaught it would reach `dispatch`'s generic `except
    Exception` and answer `error / internal`, telling an agent hx is broken
    when in fact one stored blob failed its own integrity check -- exactly
    the "tested, clean" vs "never reached" confusion section 12 rules out.
    """
    row = ctx.conn.execute(
        "SELECT req_blob, resp_blob, resp_len FROM exchange WHERE id=?",
        (exchange_id,)).fetchone()
    if row is None:
        return None
    out = []
    if part in ("request", "both") and row[0]:
        try:
            out.append(("request", ctx.blobs.get(row[0])))
        except CorruptBlob:
            pass
    if part in ("response", "both") and row[1]:
        try:
            out.append(("response", ctx.blobs.get(row[1], row[2])))
        except CorruptBlob:
            pass
    return out or None


def grep(ctx, *, exchange_ids, pattern: str, part: str = "response",
         context_bytes: int = CONTEXT_DEFAULT,
         ignore_case: bool = False) -> dict:
    """Principle 2: match-addressed reading, the documented default.

    LITERAL BYTES, NOT A REGULAR EXPRESSION, and this is a decision rather
    than an omission. Python's `re` has no timeout, the pattern here is
    agent-authored, and a catastrophic backtrack would hang the ONE
    long-lived process that also holds this engagement's Burp open -- taking
    the session, the run and the operator's halt path with it. A literal
    match cannot backtrack. It also serves what this tool is actually for:
    you search for the payload token you just sent, and `delta_vs_baseline`
    already tells you which tokens are new. Anything a literal cannot express
    is `http.body(range)`'s job, or a passive check's. Recorded as known debt
    in `docs/DECISIONS.md`.

    RULING 14 -- WHERE `unavailable` AND `empty` SPLIT. `unavailable` means
    the tool could not run at all; having searched even one exchange, it
    ran. If EVERY requested exchange is unreadable, this raises
    `ToolUnavailable("unreadable", ...)` rather than answering `empty`:
    `empty` is `envelope.answered`'s reading of a zero-row page, and to an
    agent it means "I searched and found nothing" -- which is exactly wrong
    when nothing was searchable. If even ONE exchange is readable, the
    search ran, and `ok` or `empty` plus the `unreadable` facet is honest --
    the facet names precisely which exchanges were skipped, and the agent
    can see it searched a subset rather than nothing.
    """
    needle = pattern.encode(TEXT)
    if ignore_case:
        needle = needle.lower()
    considered = exchange_ids[:MAX_EXCHANGES]
    rows, unreadable = [], []
    any_readable = False
    for xid in considered:
        found = _blobs_for(ctx, xid, part)
        if found is None:
            unreadable.append(xid)
            continue
        any_readable = True
        for part_name, data in found:
            hay = data.lower() if ignore_case else data
            at = hay.find(needle)
            while at != -1:
                start = max(0, at - context_bytes)
                end = min(len(data), at + len(needle) + context_bytes)
                rows.append({
                    "exchange_id": xid, "part": part_name, "offset": at,
                    "before": data[start:at].decode(TEXT),
                    "match": data[at:at + len(needle)].decode(TEXT),
                    "after": data[at + len(needle):end].decode(TEXT),
                })
                at = hay.find(needle, at + len(needle))
    if considered and not any_readable:
        raise ToolUnavailable(
            "unreadable",
            f"none of the {len(considered)} requested exchange(s) could be "
            "read -- surface.detail lists what this engagement actually "
            "holds.")
    # UNREADABLE IS A FACET AND NOT A SILENCE. An exchange whose blob is gone
    # is not an exchange with no matches, and section 12's rule -- a report
    # that cannot tell "tested, clean" from "never reached" is worse than no
    # report -- is exactly as true of one envelope as of a whole engagement.
    return envelope.page(rows, total=len(rows), limit=envelope.MAX_LIMIT,
                         facets={"unreadable": unreadable,
                                 "searched": len(considered)})


def body(ctx, *, exchange_id: str, start: int = 0,
         length: int = RANGE_MAX, part: str = "response") -> dict:
    """Principle 2's escape hatch, used after a match yields an offset."""
    if part == "both":
        raise ToolRefused(
            "bad_args", "http.body reads one part; 'both' is grep's default, "
                        "not a range this tool can return")
    found = _blobs_for(ctx, exchange_id, part)
    if found is None:
        raise ToolRefused(
            "bad_args",
            f"no readable {part} for exchange {exchange_id!r}. It may not "
            "exist, or its body may never have been stored -- surface.detail "
            "lists the exchanges this engagement holds.")
    _name, data = found[0]
    window = data[start:start + min(length, RANGE_MAX)]
    # ONE SHAPE, INCLUDING PAST THE END. Reading past the end is a legitimate
    # way to find the end, so it is not an error -- and it is not `empty`
    # either: `empty` is Principle 3's LIST vocabulary, and
    # `envelope.answered` reads it off a page envelope's `total == 0`. To
    # spell this `empty` would mean reporting `total: 0` for a body that is
    # 5 KB long, which is a lie about the one number an agent needs to know
    # whether it has the whole thing. `length: 0` beside the true `total`
    # says where the end is.
    return {"exchange_id": exchange_id, "part": part, "start": start,
            "length": len(window), "total": len(data),
            "bytes": window.decode(TEXT)}


registry.register(spec.ToolSpec(
    name="http.grep", handler=grep,
    summary="Search stored request/response bytes for a literal string and "
            "return each match with its offset and surrounding context.",
    params={"type": "object", "additionalProperties": False,
            "required": ["exchange_ids", "pattern"], "properties": {
                "exchange_ids": {"type": "array", "maxItems": MAX_EXCHANGES,
                                 "items": {"type": "string", "maxLength": 64}},
                "pattern": {"type": "string", "minLength": 1,
                            "maxLength": 1024,
                            "description": "a literal string, NOT a regular "
                                           "expression"},
                "part": {"type": "string", "enum": PARTS,
                         "description": "default response"},
                "context_bytes": {"type": "integer", "minimum": 0,
                                  "maximum": CONTEXT_MAX,
                                  "description": "bytes either side of each "
                                                 "match; default 64"},
                "ignore_case": {"type": "boolean"},
            }}))

registry.register(spec.ToolSpec(
    name="http.body", handler=body,
    summary="Read a bounded range of one stored request or response. Use "
            "http.grep first to find the offset.",
    params={"type": "object", "additionalProperties": False,
            "required": ["exchange_id"], "properties": {
                "exchange_id": {"type": "string", "maxLength": 64},
                "start": {"type": "integer", "minimum": 0,
                          "maximum": 1_000_000_000},
                "length": {"type": "integer", "minimum": 1,
                           "maximum": RANGE_MAX},
                "part": {"type": "string", "enum": ["request", "response"]},
            }}))


#: Identities per replay. Each one is a whole extra request against a client's
#: application, so this is a blast-radius bound rather than a performance one.
#: THE SEND CEILING IS ONE HIGHER: `include_anonymous` adds a row that is not
#: an identity and is not counted here, so a full call issues nine requests,
#: not eight. Named rather than folded in, because the bound an operator
#: reasons about is "how many sessions am I comparing" and the anonymous row
#: is the comparison rather than one of the sessions.
MAX_IDENTITIES = 8


def _parts_of(url: str, raw: bytes) -> tuple[str, str, int, str]:
    """The `(scheme, host, port, path)` one stored exchange is replayed with.

    THE ORIGIN COMES FROM THE STORED URL AND THE PATH COMES FROM THE STORED
    REQUEST LINE. That looks like an inconsistency and it is not.
    `records.redact_url` runs on EVERY write to `exchange.url`, so a stored
    url whose request carried userinfo or a credential parameter has been
    rewritten -- `{{observed:userinfo}}@app.test` for the first,
    `?token={{observed:param}}` for the second. Replaying THAT path would put
    a placeholder on the wire and ask the application a different question
    from the one under investigation, and the answer would be reported as an
    authorisation difference.

    The stored request BLOB is not rewritten by that rule. `hx.issue` stores
    the bytes this side composed and the credential is injected below it, so
    a send-path blob's request line still carries the target that was sent;
    a proxy-captured blob had the SAME redaction applied to its request line
    inside the JVM, so taking the path from there is never WORSE than taking
    it from the url. The authority has to come from the url either way: an
    origin-form request line does not carry one.
    """
    scheme, sep, rest = url.partition("://")
    if not sep:
        raise ToolRefused(
            "bad_args",
            f"the stored url {url!r} has no authority, so there is no host "
            "to replay this exchange against.")
    authority = rest
    for delim in ("/", "?", "#"):
        authority = authority.split(delim, 1)[0]
    # THE USERINFO WAS REPLACED, NOT REMOVED -- `redact_url`'s cut ends AT the
    # `@` so the result still reads as an authority. RFC 3986 3.2.1 puts
    # everything before the last `@` in the userinfo, and none of it is host.
    authority = authority.rpartition("@")[2]
    host, port = authority, issue_mod.DEFAULT_PORTS.get(scheme, 80)
    # An IPv6 literal KEEPS ITS BRACKETS: `Host:` carries them, and the colons
    # inside them are not the port delimiter. So a port is what follows the
    # LAST colon, and only when that colon is outside the brackets and what
    # follows it is ASCII digits -- `str.isdigit()` alone answers True for
    # superscript two, which `int()` then refuses.
    before, colon, after = authority.rpartition(":")
    if colon and "]" not in after and after.isascii() and after.isdigit():
        host, port = before, int(after)
    line = raw.split(b"\n", 1)[0].rstrip(b"\r").decode(TEXT)
    target = line.split(" ")
    if len(target) < 2 or not target[1].startswith("/"):
        raise ToolRefused(
            "bad_args",
            f"the stored request line {line!r} carries no origin-form target, "
            "so there is no path to replay.")
    return scheme, host, port, target[1]


def _replayed_headers(ctx, raw: bytes) -> tuple[str, ...]:
    """The stored request's header lines, minus the ones a replay must drop.

    DROPPING EVERY DECLARED IDENTITY'S HEADER IS THE LOAD-BEARING LINE OF
    THIS TOOL. The stored request may already carry a header that some
    identity injects -- a `Cookie` a proxy observation captured, a bearer
    token an earlier send was bound to. Replayed verbatim under identity B,
    that header sends identity A's credential under B's name: the application
    answers both replays as the SAME session, every row comes back identical,
    and the tool reports "no difference" for two sessions that were never two
    sessions. An authorisation finding gets written from these rows, so that
    is the one answer this tool must never give wrongly.

    EVERY DECLARED IDENTITY'S HEADER, not just the one this exchange was
    issued under. `exchange.identity` is NULL for proxy traffic and for an
    anonymous send, so the header a stored request carries is not always a
    name this side knows -- and a rule that dropped only the known one would
    be exactly as wrong on the rows where it matters most.

    RULING 15: THE DROP SET IS `config.CREDENTIAL_HEADERS` UNION THE DECLARED
    ONES, and both halves are needed. The declared half covers the identities
    THIS engagement configured. The standing half covers a credential the
    original request carried that no identity here declares -- an
    `Authorization` on an engagement whose only identity injects `Cookie` --
    and that is the case a replay is MOST likely to meet, since the natural
    agent action is replaying a request lifted from Burp's history. Without
    it the extension refuses every replay as `unmanaged_credential` before
    the Gate (`Redactor.unmanagedCredential`), so the tool is not wrong so
    much as dead: every row comes back refused and no authz table can be
    built at all. `config.CREDENTIAL_HEADERS` is IMPORTED rather than
    restated, because it is already pinned byte for byte against the
    extension's own list and a second copy is a second thing to keep in sync.

    `Content-Length` GOES TOO, for a plainer reason: `issue.request_bytes`
    computes it from the body it is handed and REFUSES a caller-supplied one
    that disagrees, because a Content-Length that does not match its body is
    a request-smuggling primitive rather than a typo to correct silently. A
    stored request whose body was shed or truncated carries exactly such a
    disagreement, so replaying the header would turn a perfectly replayable
    request into a refusal over a number this side can simply recompute.
    """
    drop = {name.lower() for name in config_mod.CREDENTIAL_HEADERS}
    drop.update(ident.inject.header.strip().lower()
                for ident in ctx.config.identities.values())
    drop.add("content-length")
    head, _body = http_text.split_head_body(raw)
    kept = []
    for line in http_text.header_lines(head):
        name, sep, _value = line.partition(b":")
        if not sep:
            continue
        if name.decode(TEXT).strip().lower() in drop:
            continue
        kept.append(line.decode(TEXT))
    return tuple(kept)


def _replayed_body(raw: bytes) -> bytes:
    """Everything after the stored request's head.

    `http_text.split_head_body` rather than a partition on CRLFCRLF, for the
    reason that function's own docstring gives: a bare-LF head matches
    nothing, and every replay of such a request would carry an EMPTY body --
    a different request from the one being investigated, answered differently
    and reported as an authorisation difference.
    """
    _head, body = http_text.split_head_body(raw)
    return body


def replay_as(ctx, *, exchange_id: str, identities,
              include_anonymous: bool = False) -> dict:
    """Re-issue one stored request under several identities and compare.

    THE BASELINE IS THE ORIGINAL EXCHANGE, not the first replay. An authz
    question is "does this identity see what that one saw", and the thing
    that was seen is the exchange the agent is pointing at. Comparing replays
    only against each other would answer a different question and would give
    no answer at all for a single identity.

    ONE IDENTITY'S REFUSAL DOES NOT DISCARD THE OTHERS. A row carries either
    a `digest` or a `refused` class, never neither and never both -- so "two
    identities, one answer and one rate limit" stays distinguishable from
    "two identities, one answer", which is section 12's rule inside one
    result.

    `include_anonymous` IS ITS OWN FLAG rather than a reserved name in
    `identities`. The unauthenticated comparison is the most valuable row in
    an authz table and a magic string could collide with an identity an
    operator declared.

    AN ORIGINAL WITH NO STORED RESPONSE BODY IS COMPARED AGAINST NOTHING, AND
    THE ROWS SAY SO. `resp_blob` is NULL for an exchange whose body was shed
    and for one whose transport failed before a response existed. Diffing
    against `b""` there would report a length delta and `differs: true` on
    EVERY row -- an authorisation difference on every single call, which is
    the one claim this tool must never make wrongly. So `differs` and
    `diff_vs_original` are null, "not computed", exactly as `delta`'s own
    `new_tokens` is null rather than `[]` when the bodies were too big to
    diff, and the `original_body_stored` facet names the reason.

    A NULL `differs` MEANS "NOT COMPUTED", NEVER "NO DIFFERENCE", and it
    happens two ways: the identity's replay was REFUSED, so there is no
    response to compare, or the original had no stored response body, so
    there is nothing to compare against. `false` is the only value that says
    the two bodies matched. An agent writing `if not row["differs"]` reads a
    row where nothing was ever sent as a clean result, which is section 12's
    "tested, clean" against "never reached" inside one key -- `refused` tells
    the two apart on the row and `original_body_stored` on the facet.
    """
    row = ctx.conn.execute(
        "SELECT req_blob, resp_blob, resp_len, status, method, url"
        " FROM exchange WHERE id=?", (exchange_id,)).fetchone()
    if row is None or row[0] is None:
        raise ToolRefused(
            "bad_args",
            f"exchange {exchange_id!r} has no stored request to replay. "
            "surface.detail lists the exchanges this engagement holds.")
    req_blob, resp_blob, resp_len, status, method, url = row
    try:
        raw = ctx.blobs.get(req_blob)
    except CorruptBlob as exc:
        # `unavailable / unreadable`, the same answer `http.grep` gives a blob
        # that fails its own digest check: the tool could not run, which is a
        # different fact from a bad argument and a very different one from a
        # defect in hx. `error / internal` here would tell an agent hx is
        # broken when one stored blob merely failed verification.
        raise ToolUnavailable(
            "unreadable",
            f"the stored request for exchange {exchange_id!r} could not be "
            f"read, so there is nothing to replay: {exc}") from exc
    # THE BODY, NOT THE WHOLE RESPONSE, and the same rule `delta.baseline_for`
    # follows for the same reason. Two replays of one request differ in their
    # `Date:` and their per-session `Set-Cookie` even when the application
    # returned byte-identical content -- so a comparison over whole responses
    # reports an authorisation difference on every single call, which is the
    # one answer this tool must never give wrongly.
    base_body = None
    if resp_blob:
        try:
            _head, base_body = http_text.split_head_body(
                ctx.blobs.get(resp_blob, resp_len))
        except CorruptBlob:
            # Not fatal the way an unreadable REQUEST is: the replays can
            # still be issued and their digests are still worth having. What
            # is lost is the comparison, and the rows say so rather than
            # diffing against bytes nobody read.
            base_body = None

    scheme, host, port, path = _parts_of(url, raw)
    headers = _replayed_headers(ctx, raw)
    body = _replayed_body(raw)
    # THE COMPOSED REQUEST IS CHECKED BEFORE ANYTHING SENDS, for the same
    # reason the identities are resolved first. `request_bytes` refuses a
    # request this side must not re-issue -- a stored `Transfer-Encoding`, a
    # target that would end the line -- with a ValueError, and one raised
    # from inside the loop below would surface as `error / internal`: hx
    # reported broken for a stored request it merely cannot replay.
    try:
        issue_mod.request_bytes(method, path, host, headers, body)
    except ValueError as exc:
        raise ToolRefused("bad_args", str(exc)) from exc

    # THE BOUND REFUSES RATHER THAN SLICING. The schema's `maxItems` already
    # holds it, so this is unreachable through `dispatch` -- but a SLICE is
    # the wrong shape for a bound whose whole subject is blast radius: relax
    # the schema and it would silently drop the identities past the eighth
    # and report a complete-looking table that never asked about them.
    wanted = list(identities)
    if len(wanted) > MAX_IDENTITIES:
        raise ToolRefused(
            "bad_args",
            f"{len(wanted)} identities is more than the {MAX_IDENTITIES} one "
            "replay may put on a client's application. Split the call.")
    # RULING 16, AND IT IS TWO PASSES RATHER THAN ONE. `ensure_identity`
    # RESOLVES AND REGISTERS, and a registration can fire the extension's
    # liveness canary against the client's application -- which is traffic. A
    # typo in the third name found after the first two had been registered
    # would be a typo found after traffic had already reached the client, and
    # that traffic is not recallable. So the check that costs NOTHING -- a
    # lookup in `config.identities`, no I/O of any kind -- runs over every
    # name before the step that can touch the client runs over any of them.
    try:
        for name in wanted:
            live.declaration_of(ctx, name)
        # ...AND ONLY NOW. Still before any SEND, which is the second half of
        # the same ruling: nothing goes on the wire until every identity has
        # a credential behind it.
        resolved = [live.ensure_identity(ctx, name) for name in wanted]
    # CATCHING THE PASS ABOVE, AND STANDING GUARD OVER THE ONE BELOW.
    # `declaration_of` raises this for an undeclared name, so the clause is
    # reached in the ordinary way. It also covers `ensure_identity`'s own
    # `ValueError` -- which the pre-pass has already made unreachable, and
    # which is kept anyway: a future refactor that drops or reorders the
    # declaration pass would otherwise turn an undeclared name into
    # `error / internal` silently, and the agent would be told hx is broken
    # for a typo it could fix.
    except ValueError as exc:
        raise ToolRefused("bad_args", str(exc)) from exc
    except identity_mod.IdentityError as exc:
        # RULING 13, and `send`'s own clauses unchanged: a DECLARED identity
        # whose credential will not resolve is an operator's missing
        # `export`, not an argument the agent could have written differently.
        raise ToolUnavailable("identity_unresolved", str(exc)) from exc
    except BridgeError as exc:
        # The extension refused the REGISTRATION itself -- through the same
        # table as a send refusal, for the reason `_raise_for_class` gives.
        cls_ = exc.error_class or "transport_error"
        detail = str(exc).removeprefix(f"{cls_}: ")
        _raise_for_class(cls_, detail, exc)
    plan = list(zip(wanted, resolved))
    if include_anonymous:
        plan.append((None, None))

    rows = []
    for name, ident in plan:
        try:
            issued = issue_mod.issue(
                ctx.session.bridge, ctx.conn, ctx.blobs, ctx.config,
                engagement_id=ctx.engagement.id, run_id=ctx.run_id,
                scheme=scheme, host=host, port=port, method=method,
                path=path, headers=headers, body=body, identity=ident)
        except issue_mod.IssueRefused as exc:
            rows.append({"identity": name, "digest": None,
                         "refused": exc.reason, "detail": exc.detail,
                         "diff_vs_original": None, "differs": None})
            continue
        rows.append({
            "identity": name, "digest": _digest(ctx, issued), "refused": None,
            "detail": None,
            "diff_vs_original": (
                None if base_body is None
                else delta_mod.against(status, base_body, issued.status,
                                       issued.body)),
            "differs": (None if base_body is None
                        else (status != issued.status
                              or base_body != issued.body)),
        })
    return envelope.page(rows, total=len(rows), limit=envelope.MAX_LIMIT,
                         facets={"original": exchange_id,
                                 "original_status": status,
                                 "original_body_stored": base_body is not None})


registry.register(spec.ToolSpec(
    name="http.replay_as", handler=replay_as, needs_egress=True, mutates=True,
    summary="Re-issue one stored request under several identities and report "
            "each one's digest and how it differs from the original. A null "
            "`differs` means NOT COMPARED -- the replay was refused, or the "
            "original's response body was never stored -- never 'the same'.",
    params={"type": "object", "additionalProperties": False,
            "required": ["exchange_id", "identities"], "properties": {
                "exchange_id": {"type": "string", "maxLength": 64},
                "identities": {"type": "array", "maxItems": MAX_IDENTITIES,
                               "items": {"type": "string", "maxLength": 64},
                               "description": "NAMES declared in config.yaml"},
                "include_anonymous": {
                    "type": "boolean",
                    "description": "also replay with no identity at all"},
            }}))
