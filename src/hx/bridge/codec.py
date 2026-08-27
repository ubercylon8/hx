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

# The header key that says the body slot holds TWO length-prefixed bodies:
#
#     [4-byte BE len(first)][first][4-byte BE len(second)][second]
#
# Plan 4's `exchange` frame carries a request and a response, and they cannot
# share one opaque body: each is content-addressed into the blob store on its
# own. The OUTER frame is unchanged -- same length prefix, header, newline and
# body slot -- so every one-body frame is byte-identical to what it was, which
# tests/vectors/frames.json pins for both codecs.
#
# In the HEADER rather than inferred from `t`: this module has no business
# knowing the frame vocabulary, and a reader that guessed from `t == "exchange"`
# would mis-parse the first two-body frame type someone adds without teaching it.
# `Frame.BODIES_KEY` is the same string on the Java side.
BODIES_KEY = "bodies"

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
        # A lone UTF-16 surrogate from a \u escape parses fine here -- json.loads
        # accepts it -- but corrupts silently later: this side raises
        # UnicodeEncodeError on re-encode, the Java side silently writes '?'.
        # Reject it at the same place the flat-type check lives, so decode()
        # and encode() both refuse it rather than letting only one side notice.
        if isinstance(value, str) and any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            raise FrameError(
                f"header string {key!r} contains an unpaired UTF-16 surrogate"
            )
        # Python integers are unbounded; the far side reads them into a signed
        # 64-bit long. Emitting a value it cannot represent would produce a frame
        # that is valid here and a hard error there.
        if isinstance(value, int) and not isinstance(value, bool):
            if not (-(2 ** 63) <= value <= 2 ** 63 - 1):
                raise FrameError(
                    f"header integer {key!r}={value} is outside signed 64-bit range"
                )


def encode(header: dict, body: bytes = b"") -> bytes:
    _check_header(header)
    head = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload = head + b"\n" + body
    if len(payload) > MAX_FRAME:
        raise FrameError(f"frame of {len(payload)} bytes exceeds MAX_FRAME {MAX_FRAME}")
    return _LEN.pack(len(payload)) + payload


def encode_two(header: dict, first: bytes, second: bytes) -> bytes:
    """One frame carrying two bodies. Mirrors `Frame.encode(header, a, b)`.

    The header is COPIED and stamped here rather than trusted from the caller,
    so the declaration on the wire cannot disagree with the shape of the bytes:
    a caller that forgot the key would produce a frame whose second body is
    read as trailing bytes of the first.

    The size is checked BEFORE the two bodies are joined, the same way and for
    the same reason as the Java side: MAX_FRAME exists so one frame cannot make
    the process allocate arbitrarily, and a check that runs after the
    allocation it bounds has already lost. This used to build the whole
    concatenation and let `encode` check afterwards -- the opposite of what the
    comment in `Frame.encode` says the two files do -- which is harmless here
    only because nothing in `src/` calls this. `test_encode_two_has_no_caller
    _outside_the_tests` is what makes that "only" a fact rather than a habit.
    """
    total = _LEN.size + len(first) + _LEN.size + len(second)
    if total > MAX_FRAME:
        raise FrameError(
            f"two bodies of {len(first)} + {len(second)} bytes exceed "
            f"MAX_FRAME {MAX_FRAME}"
        )
    payload = (_LEN.pack(len(first)) + first
               + _LEN.pack(len(second)) + second)
    return encode({**header, BODIES_KEY: 2}, payload)


def _declares_two_bodies(header: dict) -> bool:
    """Whether the header says the body slot holds two bodies.

    `2` and no other value. A `bodies` this version does not know is a frame
    it cannot read, not one to guess at -- and `bodies` is checked against a
    bool separately because `True == 1` in Python and a header is allowed to
    carry bools, so `bodies: True` would otherwise sail past an `== 1` test on
    a future version that accepted one.
    """
    if BODIES_KEY not in header:
        return False
    value = header[BODIES_KEY]
    if value == 2 and not isinstance(value, bool):
        return True
    raise FrameError(
        f"header declares {BODIES_KEY}={value!r}; this version reads 2 and no "
        "other value"
    )


def _body_spans(payload: bytes) -> tuple[int, int, int, int]:
    """(start, end) of each body, or FrameError.

    EXACT FIT is required: the two declared lengths must consume the payload to
    its last byte. Bytes left over are bytes the two implementations would read
    differently, and the lengths are on the wire precisely so neither side has
    to guess where a half ends.
    """
    if len(payload) < _LEN.size:
        raise FrameError("two-body frame has no length prefix for its first body")
    (n1,) = _LEN.unpack_from(payload, 0)
    if len(payload) < _LEN.size + n1 + _LEN.size:
        raise FrameError(
            f"two-body frame declares a first body of {n1} but holds "
            f"{len(payload)} bytes"
        )
    (n2,) = _LEN.unpack_from(payload, _LEN.size + n1)
    if len(payload) != 2 * _LEN.size + n1 + n2:
        raise FrameError(
            f"two-body frame declares bodies of {n1} + {n2}, which do not fill "
            f"its {len(payload)} bytes"
        )
    first = _LEN.size
    second = 2 * _LEN.size + n1
    return first, first + n1, second, second + n2


def split_bodies(header: dict, payload: bytes) -> tuple[bytes, bytes]:
    """The two halves of a two-body frame. Mirrors `Frame.Decoded.second`.

    Raises FrameError when the header does not declare the two-body form: a
    caller asking for two halves of a one-body frame has misread the frame, and
    handing it `(payload, b"")` would turn that into a silently empty response.
    """
    if not _declares_two_bodies(header):
        raise FrameError(
            f"frame does not declare {BODIES_KEY}=2, so it has one body, not two"
        )
    a, b, c, d = _body_spans(payload)
    return payload[a:b], payload[c:d]


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
    # THE TWO-BODY SPLIT IS NOT DONE HERE, and that is a decision rather than
    # an omission. `decode` raising FrameError is how `_serve` learns the
    # stream is unreadable, and it answers by CLOSING -- which drops the far
    # side to DENY-ALL and takes the `halt` path down with it. The outer frame
    # is well-formed here; only the packing INSIDE the body slot is wrong, and
    # a capture frame that was packed wrong must not cost the operator their
    # control channel (S4: a lost record changes what hx knows, never what it
    # allows). So the split happens at `split_bodies`, which `BridgeServer`
    # calls where the failure can be counted and contained.
    #
    # Java's `Frame.decode` DOES split eagerly. The asymmetry is real and it
    # is bounded: two-body frames travel Burp -> Python only, so that path is
    # exercised by CodecTest's own round trip and by nothing on the wire.
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
