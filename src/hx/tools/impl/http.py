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

from ... import delta as delta_mod
from ... import identity as identity_mod
from ... import issue as issue_mod
from ...bridge.server import BridgeError
from .. import live, registry, spec
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
REASON_FOR_CLASS = {
    "scope_denied": ("refused", "scope_denied"),
    "method_denied": ("refused", "method_denied"),
    "dangerous_denied": ("refused", "dangerous_denied"),
    "rate_limited": ("refused", "rate_limited"),
    "budget_exhausted": ("refused", "budget_exhausted"),
    "bad_frame": ("refused", "bad_frame"),
    "halted": ("refused", "halted"),
    # An identity the extension's own liveness canary has declared dead: a
    # `register_identity` refusal, not a send refusal -- the one class this
    # table maps that never comes off `issue()`. See `send`'s
    # `except BridgeError` below.
    "identity_dead": ("unavailable", "identity_dead"),
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
