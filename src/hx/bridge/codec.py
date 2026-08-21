"""Frame codec for the Burp bridge.

    [4-byte BE length][header JSON]\\n[body bytes]

The header is a FLAT JSON object -- string keys, and values only of type
string, int, bool or None. That restriction exists for the far side: the Burp
extension is a zero-dependency Java jar with a hand-rolled parser, and a flat
schema is small enough to be obviously correct. Structured payloads travel in
the body, which is opaque bytes.
"""
from __future__ import annotations

import json
import socket
import struct

PROTOCOL_VERSION = 1
MAX_FRAME = 64 * 1024 * 1024        # a length prefix is attacker-influenced input
_LEN = struct.Struct(">I")

CONFIG_KEYS = frozenset(
    {
        "scope.include",
        "scope.exclude",
        "dangerous.path",
        "method.allow",
        "limit.rate_rps",
        "limit.concurrency",
        "limit.max_requests",
        "render.allow",
    }
)


class Incomplete(Exception):
    """The buffer holds less than one whole frame. Normal on a stream socket."""


class FrameError(Exception):
    """The bytes are not a valid frame, or the header is not encodable."""


class PeerClosed(Exception):
    """The far end went away. Distinct from Incomplete, which means "call
    again"; conflating them makes a caller busy-loop against a dead socket."""


def _check_header(header: dict) -> None:
    for required in ("v", "t"):
        if required not in header:
            raise FrameError(f"header is missing required field {required!r}")
    for key, value in header.items():
        if not isinstance(key, str):
            raise FrameError(f"header keys must be strings, got {type(key).__name__}")
        if not isinstance(value, (str, int, bool, type(None))):
            raise FrameError(
                f"header must be flat: {key!r} is {type(value).__name__}, and the "
                "Java parser reads only string/int/bool/null"
            )


def encode(header: dict, body: bytes = b"") -> bytes:
    _check_header(header)
    head = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload = head + b"\n" + body
    if len(payload) > MAX_FRAME:
        raise FrameError(f"frame of {len(payload)} bytes exceeds MAX_FRAME {MAX_FRAME}")
    return _LEN.pack(len(payload)) + payload


def decode(buf: bytes) -> tuple[dict, bytes, int]:
    if len(buf) < _LEN.size:
        raise Incomplete("need a length prefix")
    (length,) = _LEN.unpack_from(buf, 0)
    if length > MAX_FRAME:
        raise FrameError(f"declared frame of {length} bytes exceeds MAX_FRAME {MAX_FRAME}")
    end = _LEN.size + length
    if len(buf) < end:
        raise Incomplete(f"need {end} bytes, have {len(buf)}")

    payload = buf[_LEN.size : end]
    nl = payload.find(b"\n")
    if nl < 0:
        raise FrameError("header has no newline terminator")
    try:
        header = json.loads(payload[:nl].decode("utf-8"))
    except ValueError as exc:  # UnicodeDecodeError is a ValueError
        raise FrameError(f"header is not valid JSON: {exc}") from exc
    if not isinstance(header, dict):
        raise FrameError("header must be a JSON object")
    # Validate on receipt too, not only on send. The flat restriction exists to
    # bound what the far side may produce, so this is the one place that can
    # actually defend it against a peer that ignores the contract.
    _check_header(header)
    return header, payload[nl + 1 : end], end


class FrameReader:
    """Reads frames from a socket, owning the buffer across calls.

    A bare ``read_frame(sock)`` function cannot be correct here. ``decode``
    reports ``bytes_consumed`` precisely because one ``recv`` may deliver more
    than one frame, and a function that returns after the first frame has
    nowhere to put the remainder -- so it drops it, and the loss surfaces later
    as a misleading "peer closed mid-frame". Owning the buffer is that
    somewhere.

    It also reads the length prefix before attempting a decode, so draining a
    large frame is linear rather than re-parsing a growing buffer per chunk.
    """

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self._buf = bytearray()

    def read(self) -> tuple[dict, bytes]:
        while True:
            if len(self._buf) >= _LEN.size:
                (length,) = _LEN.unpack_from(self._buf, 0)
                if length > MAX_FRAME:
                    raise FrameError(
                        f"declared frame of {length} bytes exceeds MAX_FRAME {MAX_FRAME}"
                    )
                end = _LEN.size + length
                if len(self._buf) >= end:
                    header, body, consumed = decode(bytes(self._buf[:end]))
                    del self._buf[:consumed]
                    return header, body
            chunk = self.sock.recv(65536)
            if not chunk:
                raise PeerClosed(
                    "peer closed mid-frame" if self._buf else "peer closed"
                )
            self._buf.extend(chunk)


def build_config_body(pairs: dict[str, list[str]]) -> bytes:
    out = bytearray()
    for key, values in pairs.items():
        if key not in CONFIG_KEYS:
            raise FrameError(f"unrecognised config key {key!r}")
        for value in values:
            if "\t" in value or "\n" in value:
                raise FrameError(
                    f"config value for {key!r} contains a tab or newline; "
                    "such values are rejected rather than escaped"
                )
            out += key.encode("utf-8") + b"\t" + value.encode("utf-8") + b"\n"
    return bytes(out)


def parse_config_body(body: bytes) -> dict[str, list[str]]:
    pairs: dict[str, list[str]] = {}
    for raw_line in body.decode("utf-8").split("\n"):
        if not raw_line:
            continue
        if "\t" not in raw_line:
            raise FrameError(f"config line has no tab separator: {raw_line!r}")
        key, value = raw_line.split("\t", 1)
        if key not in CONFIG_KEYS:
            raise FrameError(f"unrecognised config key {key!r}")
        pairs.setdefault(key, []).append(value)
    return pairs
