"""Reading an HTTP message off the wire, for anything holding raw bytes.

These four were `hx.checks.passive._http`'s until Plan B needed them one layer
down. `hx.issue` writes the exchange row a send produces, and has to read a
status line and a content type out of the same kind of bytes a passive check
reads.

THE ALTERNATIVES WERE BOTH WORSE. A core module importing from
`hx.checks.passive` inverts the dependency -- `checks` is built on the store
and the wire, not the other way round -- and a second copy of
`split_head_body` is the thing this repo keeps naming: a copy is what drifts.
The rules below were each earned by a specific failure (a bare-LF response
read as an empty body; a `Set-Cookie` parser that checked one cookie of five),
and a second copy is a second place for the next such failure to be fixed
only once.

`_http` re-exports all four under the names it already used, so no call site
in `hx/checks/` changes and the behavioural tests that earned these rules stay
where they are.
"""
from __future__ import annotations


def split_head_body(raw: bytes) -> tuple[bytes, bytes]:
    """Head and body, accepting either line terminator.

    RFC 9112 s2.2 requires a recipient to accept a bare LF as a line
    terminator. `partition(b"\\r\\n\\r\\n")` on a bare-LF response matches
    nothing and returns `(raw, b"", b"")`, which hands every body-searching
    check an EMPTY body and every header-reading check the whole response as
    one unsplit head. The tool then answers `clean` because it failed to
    read, which is the one direction an assessment must never be wrong in.

    Whichever terminator appears FIRST is the real one, so a body that
    happens to contain `\\r\\n\\r\\n` cannot pull the boundary backwards past
    a head that actually ended with a bare `\\n\\n`.
    """
    crlf = raw.find(b"\r\n\r\n")
    lf = raw.find(b"\n\n")
    if crlf == -1 and lf == -1:
        return raw, b""
    if crlf != -1 and (lf == -1 or crlf <= lf):
        return raw[:crlf], raw[crlf + 4:]
    return raw[:lf], raw[lf + 2:]


def header_lines(head: bytes) -> list[bytes]:
    """Header lines, minus the status line, for either terminator.

    Splits on LF and strips at most one trailing CR per line, rather than
    also splitting on a bare CR: a lone CR inside a header value is data, and
    splitting on it would invent a header boundary the wire did not carry.
    """
    return [line[:-1] if line.endswith(b"\r") else line
            for line in head.split(b"\n")[1:]]


def header_names(head: bytes) -> list[str]:
    return [line.partition(b":")[0].decode("latin-1").strip()
            for line in header_lines(head) if b":" in line]


def header_values(head: bytes, name: str) -> list[str]:
    """Every value for one header name, ASCII-case-insensitively.

    A list, not a value: `Set-Cookie` legitimately repeats, and a parser that
    returned the first would check one cookie of five and report the surface
    clean.
    """
    want = name.lower()
    out = []
    for line in header_lines(head):
        key, sep, value = line.partition(b":")
        if sep and key.decode("latin-1").strip().lower() == want:
            out.append(value.decode("latin-1").strip())
    return out
