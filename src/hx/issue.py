"""The one route from the tool layer to the wire, and the only writer of
`via='send'` exchange rows.

WHAT WAS MISSING. `src/hx/store/schema.sql` says it plainly: "`Capture.java`
delivers `via: proxy` and nothing else, so this build stores no send-path
exchange row at all." The Java confirms it -- `via` is written in exactly two
places, both in `proxy/Capture.java`, and `send/Sender.java` returns a result
map without ever pushing an `exchange` frame. Meanwhile spec section 8's
digest opens with `exchange_id`, and `http.grep`, `http.body` and
`evidence.attach` are each defined as a read keyed on one. Six tools rested on
a row nothing wrote. This module writes it.

FROM PYTHON, NOT FROM JAVA, and the trade is worth saying out loud. The result
frame already carries the redacted response bytes, the status, the timing and
the outcome; the request bytes are the ones this side composed. That is
everything the `exchange` table needs. What a Java change would add is the
POST-INJECTION request bytes and the resolved IP -- and would cost a second
writer into a table whose proxy writer took a plan to get right.

SO `req_blob` IS WHAT HX ASKED TO BE SENT, NOT WHAT LEFT THE JVM. They differ
by the identity header the extension injects. That difference is in the SAFE
direction and is the reason this is tolerable rather than merely cheap: the
credential is injected inside the JVM, so it cannot be in the bytes this side
hashes, and the blob store is content-addressed -- hashing raw bytes and
redacting afterwards would mean the raw bytes are already on disk. An agent
that needs to know an identity applied reads `exchange.identity`, which this
module writes, rather than grepping the request blob for a header it will
never find there.

A REFUSAL RAISES, and the argument is `hx.checks.probe`'s rule one word for
word: a sender that RETURNED a refusal would leave a caller free to read it as
a response. `BridgeServer.send` never returns one -- it raises `BridgeError`
with the wire's class on `.error_class` -- and this module raises
`IssueRefused` with that class as its reason.

`resolved_ip` AND `scope_version_id` STAY NULL, because the proxy writer
leaves both NULL too. Filling one here and not there would make `via` the
thing that decides how much a row knows.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import capture as capture_mod
from . import http_text
from . import surface as surface_mod
from .bridge.server import BridgeError, BridgeServer
from .store import db as db_mod
from .store import records

#: Bytes that end a line or terminate a string, in any position of a request
#: line or a header. One request becoming two is the whole of request
#: smuggling, and a `\r\n` an agent put in a path would do it below the gate
#: -- the extension decides about the request it was handed, and the second
#: request was never handed to it.
FORBIDDEN = ("\r", "\n", "\0")

#: Default scheme ports, omitted from the stored URL so a send and a proxy
#: observation of the same endpoint normalise onto ONE surface. Burp's own URL
#: omits them, and a surface split by nothing but the writer would double
#: every coverage figure.
DEFAULT_PORTS = {"http": 80, "https": 443}


class IssueRefused(Exception):
    """The request did not produce an answer. `reason` is the wire's class."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class Issued:
    """Spec section 8's digest, plus the bytes for a caller that wants them.

    `response` is the REDACTED response, whole, and it is here so that
    `http.replay_as` can compare two replies without a second round trip to
    the blob store it just wrote. `body` is `response`'s payload alone, split
    from the head with `http_text.split_head_body` -- what `body_sha256`
    hashes and what `hx.delta` diffs. Neither is part of what a tool returns
    to an agent: Principle 1 is handles and digests, never payloads.

    `bytes` AND `body_sha256` DELIBERATELY DESCRIBE DIFFERENT SPANS OF THE
    SAME RESPONSE. `bytes` counts the WHOLE redacted response, because that
    is the number the extension's own frame reports and the two must not
    disagree; `body_sha256` hashes only the PAYLOAD, because that is the span
    `http.grep` and `http.replay_as` mean by "the body" and the one section 8
    named the field for. Two byte-identical bodies with a fresh `Date:` or a
    per-session `Set-Cookie` would hash differently if this hashed the whole
    response -- reporting an authorisation difference that does not exist.
    """

    exchange_id: str
    status: int | None
    bytes: int
    ms: int
    outcome: str
    content_type: str | None
    body_sha256: str
    first_line: str
    response: bytes
    body: bytes


def _url(scheme: str, host: str, port: int, path: str) -> str:
    if DEFAULT_PORTS.get(scheme) == port:
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"


def _clean(what: str, value: str) -> str:
    for ch in FORBIDDEN:
        if ch in value:
            raise ValueError(
                f"{what} contains {ch!r}, which would end the line: "
                f"{value!r}. One request becoming two is the whole of request "
                "smuggling, and it would happen BELOW the gate -- the "
                "extension decides about the request it was handed, and the "
                "second request was never handed to it.")
    return value


def request_bytes(method: str, path: str, host: str,
                  headers=(), body: bytes = b"") -> bytes:
    """One origin-form HTTP/1.1 request, or a ValueError.

    HEADERS ARE WIRE LINES, `Name: value`, not a mapping. `hx.tools.schema`
    requires `additionalProperties: false` on every object it publishes, so a
    free-key map is not expressible as a tool argument at all -- and an array
    of lines is what HTTP itself carries, so the agent writes what the wire
    will hold rather than a shape this side has to flatten.

    A ValueError, never an `IssueRefused`: nothing on the wire said no, a
    caller made a mistake, and an `IssueRefused` would land in a journal row
    as an ordinary refusal indistinguishable from a rate limit -- the same
    distinction `hx.checks.probe.ProbeSender.get` draws for the same reason.

    FRAMING IS THIS FUNCTION'S OWN PROBLEM, not its caller's. A non-empty
    body with no `Content-Length` and no `Transfer-Encoding` is, per RFC 9112
    S6.3, a request with a ZERO-LENGTH body -- the peer stops reading at the
    blank line, and the bytes this function put after it sit in the
    connection buffer to be parsed as the START of the NEXT request on that
    keep-alive connection. That is request splitting, produced by the exact
    function whose `FORBIDDEN` guard above exists to stop it, and the JVM
    does not repair it: `Sender.wireBytes` appends the body verbatim and
    computes no length of its own. So: no framing header given and a
    non-empty body means one is COMPUTED here.

    A caller-supplied `Content-Length` that disagrees with `len(body)`, and
    any `Transfer-Encoding` at all, are both REFUSALS rather than
    corrections. A CL/TE mismatch -- or two framing mechanisms naming two
    different lengths for the same message -- is a request-smuggling
    primitive in its own right (CL.TE / TE.CL), and this seam is not where
    one gets built by accident: correcting it silently would make the
    request this function sends different from the one the caller asked for,
    which is worse than refusing. Deliberate desync testing needs a
    different tool than the one every agent request goes through.
    """
    _clean("method", method)
    _clean("path", path)
    if " " in method or not method:
        raise ValueError(f"method must be one token, got {method!r}")
    if not path.startswith("/"):
        raise ValueError(
            f"path must be origin-form and start with '/', got {path!r}")
    if " " in path:
        raise ValueError(
            f"path contains a space, which ends the request target: {path!r}. "
            "Percent-encode it.")
    lines = [f"{method} {path} HTTP/1.1"]
    given = []
    has_content_length = False
    for line in headers:
        _clean("header", line)
        if ":" not in line:
            raise ValueError(
                f"header {line!r} has no ':'; headers are wire lines of the "
                "form 'Name: value'")
        name, _, value = line.partition(":")
        if not name or name[0] in " \t":
            raise ValueError(
                f"header {line!r} has an empty or whitespace-led field "
                "name. RFC 9112 has no field name that starts with "
                "whitespace -- that shape is obs-fold, which some parsers "
                "reject and some fold into the PRECEDING header, and an "
                "agent-supplied header line is not the place either "
                "behaviour is safe to invite.")
        lname = name.strip().lower()
        if lname == "transfer-encoding":
            raise ValueError(
                f"header {line!r} sets Transfer-Encoding, refused outright. "
                "A Content-Length/Transfer-Encoding disagreement is a "
                "request-smuggling primitive (CL.TE / TE.CL), and this seam "
                "is not where one gets built by accident -- deliberate "
                "desync testing needs a different tool than the one every "
                "agent request goes through.")
        if lname == "content-length":
            try:
                declared = int(value.strip())
            except ValueError:
                raise ValueError(
                    f"header {line!r} is not a valid Content-Length "
                    "integer") from None
            if declared != len(body):
                raise ValueError(
                    f"header {line!r} disagrees with the body actually "
                    f"given ({len(body)} bytes). A Content-Length that does "
                    "not match its body is a request-smuggling primitive, "
                    "not a typo to silently correct.")
            has_content_length = True
        given.append(line)
    # THE CALLER'S HOST WINS AND IS NOT JOINED BY A SECOND. A virtual-host
    # test needs to spell `Host:` itself, and two Host headers is a smuggling
    # primitive rather than a preference.
    if not any(line.partition(":")[0].strip().lower() == "host"
               for line in given):
        lines.append(f"Host: {host}")
    lines += given
    if body and not has_content_length:
        lines.append(f"Content-Length: {len(body)}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + body


def issue(bridge, conn, blobs, config, *, engagement_id: str,
          run_id: str, scheme: str, host: str, port: int, method: str,
          path: str, headers=(), body: bytes = b"", identity=None,
          timeout: float = 30.0) -> Issued:
    """Send one request and record it. Raises `IssueRefused` on every refusal.

    `identity` is `(id, generation)` or None -- NEVER a `Resolved`. Principle
    5 keeps the credential below the tool layer, and a function that took one
    could put it in a return value that gets journalled. The extension holds
    the secret; this side holds the name, sends it as `identity_id`, and
    stores it on the row.
    """
    raw = request_bytes(method, path, host, headers, body)
    req = {"target_host": host, "target_port": port, "tls": scheme == "https"}
    if identity is not None:
        # PRESENT ONLY WHEN BOUND. See `ProbeSender.get` -- an absent key is
        # anonymous, and a null would leave the extension deciding what a
        # null means.
        req["identity_id"] = identity[0]

    try:
        result = bridge.send(req, raw, timeout=timeout)
    except BridgeError as exc:
        cls = exc.error_class or "transport_error"
        detail = str(exc).removeprefix(f"{cls}: ")
        raise IssueRefused(cls, "" if detail == cls else detail) from exc

    # `BridgeServer.BODY_KEY` directly, not `type(bridge).BODY_KEY`: the test
    # double in `tests/test_probe.py` reproduces the real reply SHAPE without
    # subclassing `BridgeServer`, and this module has to read that shape too.
    response = result.get(BridgeServer.BODY_KEY, b"")
    status = result.get("status")
    outcome = result.get("outcome", "ok")
    ms = int(result.get("ms") or 0)
    head, response_body = http_text.split_head_body(response)
    types = http_text.header_values(head, "content-type")
    first_line = head.split(b"\n", 1)[0].rstrip(b"\r").decode(
        "latin-1", "replace")

    url = _url(scheme, host, port, path)
    norm = surface_mod.normalise(
        method, url,
        preserve=frozenset(config.preserve_segments),
        slug_threshold=config.slug_threshold)

    # BLOBS BEFORE THE TRANSACTION, deliberately, and the argument is the
    # proxy writer's: the blob store is not in the database, so a ROLLBACK
    # cannot take a file back. Writing them first leaves an orphan blob a
    # sweep can collect; writing them after a committed row that NAMES them
    # would leave corruption a report reads as evidence.
    req_blob, _ = blobs.put(raw)
    resp_blob, resp_len = blobs.put(response) if response else (None, None)

    cap = capture_mod.Capture(conn=conn, blobs=blobs,
                              engagement_id=engagement_id, config=config)
    at = capture_mod.now_us()
    with db_mod.transaction(conn):
        exchange_id = records.record_exchange(
            conn, run_id=run_id, method=method, url=url, status=status,
            req_blob=req_blob, resp_blob=resp_blob, resp_len=resp_len,
            ms=ms, at_us=at, outcome=outcome, via="send",
            identity=None if identity is None else identity[0],
            identity_generation=None if identity is None else identity[1],
            # NEVER `proven`. A canary bracket proves a RUN (spec section 6);
            # one send has no bracket, so `assumed` is the whole of what is
            # known and `proven` would be a claim no canary backs.
            identity_state=None if identity is None else "assumed")
        # S5's coverage floor, and the proxy writer bumps it for the same
        # reason: a run that sent a hundred requests and reports having
        # issued none makes every figure derived from this column wrong.
        conn.execute(
            "UPDATE run SET requests_issued = requests_issued + 1"
            " WHERE id=?", (run_id,))
        surface_id = cap.upsert_surface(norm, exchange_id=exchange_id,
                                        run_id=run_id, via="send")
        # The back-reference, and it cannot be written earlier: the surface's
        # exemplar is this exchange, so the exchange row has to exist before
        # the surface row can name it.
        conn.execute("UPDATE exchange SET surface_id=? WHERE id=?",
                     (surface_id, exchange_id))

    return Issued(
        exchange_id=exchange_id, status=status, bytes=len(response), ms=ms,
        outcome=outcome, content_type=types[0] if types else None,
        # HASHES THE BODY, NOT `response`. `bytes` above is the whole
        # redacted response -- it has to match the extension's own frame --
        # while this is the payload alone; see `Issued`'s docstring for why
        # the two spans differ on purpose and are not a mismatch to "fix".
        body_sha256="sha256:" + hashlib.sha256(response_body).hexdigest(),
        first_line=first_line, response=response, body=response_body)
