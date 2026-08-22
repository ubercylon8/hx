# hx Bridge Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the wire between Burp and the harness — a Unix-socket bridge on which Burp dials in, completes a `hello` / `configure` / epoch handshake, and refuses every request until it is configured.

**Architecture:** Python listens, Burp dials in — the harness holds the state and outlives Burp, so a Burp restart is a reconnect rather than an outage. Frames are `[4-byte BE length][JSON header][raw body bytes]`, control in the header and payload in bytes, so a 1.2 MB response pays no base64 tax. The extension is a zero-dependency Java jar built with `javac` and `jar`; it carries a hand-rolled codec for a deliberately flat header schema. DENY-ALL is the initial and terminal state.

**Tech Stack:** Python 3.12+ (stdlib `socket`, `struct`, `json`), Java 21 target compiled by JDK 26 with `--release 21`, `pytest`. No build tool, no third-party dependency on either side.

**Spec:** `docs/superpowers/specs/2026-08-21-hx-design.md` (§4 enforcement invariant, §6 bridge protocol)

**Depends on:** Plan 1 (engagement store) — merged as PR #1. This plan consumes `hx.engagement.Engagement`, `hx.store.db.connect` and `hx.config.Config`.

## Global Constraints

- Python 3.12 minimum. Java compiled with `--release 21` (Burp targets 21; the local JDK is 26).
- **The extension has zero third-party dependencies.** Built by `javac` + `jar` against `montoya-api.jar` as `compileOnly`. Do not introduce Gradle, Maven, or a JSON library.
- Socket directory mode `0o700`, socket mode `0o600`, a **fresh random basename per run**, unlinked on shutdown. Refuse to start if the path already exists.
- `SO_PEERCRED` is checked on every accept: the peer's uid must equal our own. The socket authenticates a uid, not a program, so also log the peer pid and its executable path.
- **Maximum frame size is 64 MiB.** A length prefix is attacker-influenced input; never allocate on it before checking it.
- Every header carries `v` (protocol version, integer) and `t` (frame type). Request/response frames additionally carry `id` (monotonic integer) and `deadline_us` (absolute microseconds). This plan *sets and validates* `deadline_us` so the frame shape is stable; *acting* on it belongs to Plan 3's send path.
- **DENY-ALL is the initial and terminal state.** Until a `configure` frame is received and its `config_epoch` acknowledged, every `send` is refused with error class `not_configured`.
- An `engagement_id` mismatch between `hello` and the open engagement is fatal: the harness closes the connection and records the attempt.
- All timestamps are integer microseconds since epoch, suffix `_us`.
- No network sockets. This plan uses `AF_UNIX` only; nothing talks to a target.

---

### Task 1: Wire format, shared golden vectors, and the Python codec

**Files:**
- Create: `docs/bridge-protocol.md`
- Create: `tests/vectors/frames.json`
- Create: `src/hx/bridge/__init__.py`
- Create: `src/hx/bridge/codec.py`
- Test: `tests/test_bridge_codec.py`

**Interfaces:**
- Consumes: nothing from Plan 1
- Produces:
  - `hx.bridge.codec.PROTOCOL_VERSION: int` — `1`
  - `hx.bridge.codec.MAX_FRAME: int` — `64 * 1024 * 1024`
  - `hx.bridge.codec.encode(header: dict, body: bytes = b"") -> bytes`
  - `hx.bridge.codec.decode(buf: bytes) -> tuple[dict, bytes, int]` — returns `(header, body, bytes_consumed)`; raises `Incomplete` when `buf` holds less than one whole frame
  - `hx.bridge.codec.FrameReader(sock)` with `.read() -> tuple[dict, bytes]` — owns the buffer across calls
  - `hx.bridge.codec.PeerClosed(Exception)`
  - `hx.bridge.codec.Incomplete(Exception)`, `hx.bridge.codec.FrameError(Exception)`
  - `hx.bridge.codec.parse_config_body(body: bytes) -> dict[str, list[str]]`
  - `hx.bridge.codec.build_config_body(pairs: dict[str, list[str]]) -> bytes`

- [ ] **Step 1: Write the protocol document**

This is the contract two implementations must agree on, so it is written down once and both sides are tested against it.

```markdown
# hx bridge wire protocol v1

## Framing

    [4-byte big-endian unsigned length][header bytes][body bytes]

`length` counts header + body. It is attacker-influenced: reject anything
above MAX_FRAME (64 MiB) before allocating.

The header is a **flat** JSON object, UTF-8, terminated by a newline (`\n`).
Everything after that newline, to the end of the frame, is the body.

Flat means: string keys, and values that are only string, integer, boolean or
null. No nested objects, no arrays. This keeps the Java parser small enough to
be obviously correct. Structured payloads travel in the body.

## Header fields

Every frame:
  v          integer  protocol version, currently 1
  t          string   frame type

Request/response frames (`send`, `result`, `error`, `configure`, `configured`):
  id         integer  monotonic, set by the sender of the request
  deadline_us integer absolute microseconds; the receiver abandons work past it

## Two things a second implementation must match

**Key order is preserved on the wire.** The header is written in insertion
order, and the golden vectors compare exact bytes. A writer using an unordered
map produces a semantically identical header with different bytes and fails the
vector comparison. Parsing is order-independent; only the byte comparison cares.

**Header integers are 64-bit signed.** `deadline_us` is absolute microseconds
since epoch -- about 1.79e15 today, which overflows a 32-bit integer by roughly
six orders of magnitude. Parse header numbers into a 64-bit type. Floats and
exponents are not valid header numbers.

**Non-ASCII header values are raw UTF-8, not `\uXXXX` escapes.** Only the
characters JSON requires are escaped: `"` `\\` and the control characters.

## Frame types

  burp -> py   hello       {v,t,ext_version,pid,burp_version,instance_id,engagement_id}
  py -> burp   configure   {v,t,id,deadline_us,engagement_id,scope_sha256,profile}
                           body: config lines (below)
  burp -> py   configured  {v,t,id,config_epoch}
  py -> burp   send        {v,t,id,deadline_us,identity_id,target_host,target_port,tls}
                           body: raw HTTP request bytes
  burp -> py   result      {v,t,id,exchange_id,status,bytes,ms,outcome}
                           body: raw HTTP response bytes
  burp -> py   error       {v,t,id,class,detail}
  burp -> py   exchange    {v,t,...}   unsolicited; no id. Defined in a later plan.
  py -> burp   halt        {v,t,id,deadline_us,reason}
  py -> burp   resume      {v,t,id,deadline_us}

## Config body format

The `configure` body is NOT JSON. It is a line-oriented format, because the
extension parses it and a flat parser cannot express nested config:

    key<TAB>value\n

Repeated keys accumulate into a list, in order. Keys and values are UTF-8.
A value may not contain a tab or a newline; the sender rejects such input
rather than escaping it.

Recognised keys:

    scope.include      URL pattern, repeatable
    scope.exclude      URL pattern, repeatable
    dangerous.path     path pattern, repeatable
    method.allow       HTTP method, repeatable
    limit.rate_rps     integer, once
    limit.concurrency  integer, once
    limit.max_requests integer, once
    render.allow       host pattern, repeatable

An unrecognised key is an error, not a warning: silently ignoring a key the
sender believed it set is how a scope rule goes missing.
```

Write that verbatim to `docs/bridge-protocol.md`.

- [ ] **Step 2: Write the shared golden vectors**

Both the Python and the Java codec are tested against this same file. It is the only thing preventing the two implementations from drifting apart while each passes its own tests.

```json
{
  "comment": "Shared codec vectors. BOTH the Python and Java codec tests run against this file. hex is the complete frame including the 4-byte length prefix.",
  "frames": [
    {
      "name": "hello_minimal",
      "header": {"v": 1, "t": "hello", "pid": 4171},
      "body_utf8": "",
      "hex": "0000001f7b2276223a312c2274223a2268656c6c6f222c22706964223a343137317d0a"
    },
    {
      "name": "header_with_bool_and_null",
      "header": {"v": 1, "t": "send", "tls": true, "identity_id": null},
      "body_utf8": "",
      "hex": ""
    },
    {
      "name": "body_with_crlf",
      "header": {"v": 1, "t": "send", "id": 7},
      "body_utf8": "GET / HTTP/1.1\r\nHost: a\r\n\r\n",
      "hex": ""
    },
    {
      "name": "body_with_embedded_newline_and_utf8",
      "header": {"v": 1, "t": "result", "id": 9, "status": 200},
      "body_utf8": "line1\nline2 éü中",
      "hex": ""
    },
    {
      "name": "empty_header_values",
      "header": {"v": 1, "t": "error", "id": 3, "class": "scope_denied", "detail": ""},
      "body_utf8": "",
      "hex": ""
    },
    {
      "name": "header_value_needing_json_escapes",
      "header": {"v": 1, "t": "error", "id": 4, "detail": "quote\" back\\ tab\t nl\n ctrl\u0001"},
      "body_utf8": "",
      "hex": ""
    },
    {
      "name": "header_value_non_ascii",
      "header": {"v": 1, "t": "error", "id": 5, "detail": "éü中 \u00e9"},
      "body_utf8": "",
      "hex": ""
    },
    {
      "name": "header_integer_beyond_int32",
      "header": {"v": 1, "t": "send", "id": 6, "deadline_us": 1787355131378277},
      "body_utf8": "",
      "hex": ""
    },
    {
      "name": "header_negative_integer",
      "header": {"v": 1, "t": "result", "id": 7, "ms": -1},
      "body_utf8": "",
      "hex": ""
    },
    {
      "name": "empty_body_is_zero_bytes_not_absent",
      "header": {"v": 1, "t": "hello", "id": 8},
      "body_utf8": "",
      "hex": ""
    }
  ]
}
```

The `hex` field is left empty for all but the first vector deliberately: Step 5 fills them in from the Python encoder once it exists, and the Java test then asserts against those exact bytes. Filling them by hand invites a typo that both implementations would then agree on.

- [ ] **Step 3: Write the failing tests**

```python
# tests/test_bridge_codec.py
import json
import socket
from pathlib import Path

import pytest

from hx.bridge import codec

VECTORS = Path(__file__).parent / "vectors" / "frames.json"


def test_round_trip_simple():
    raw = codec.encode({"v": 1, "t": "hello", "pid": 4171})
    header, body, consumed = codec.decode(raw)
    assert header == {"v": 1, "t": "hello", "pid": 4171}
    assert body == b""
    assert consumed == len(raw)


def test_body_bytes_survive_verbatim():
    """No base64, no re-encoding: the body is bytes in and bytes out."""
    payload = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n\x00\xff\xfe binary"
    raw = codec.encode({"v": 1, "t": "send", "id": 1}, payload)
    header, body, _ = codec.decode(raw)
    assert body == payload


def test_body_containing_a_newline_does_not_confuse_the_header_split():
    """The header ends at the FIRST newline. A body full of them must not matter."""
    payload = b"\n\n\n{\"not\":\"a header\"}\n"
    raw = codec.encode({"v": 1, "t": "send", "id": 2}, payload)
    header, body, _ = codec.decode(raw)
    assert header["t"] == "send"
    assert body == payload


def test_large_body_round_trips():
    payload = bytes(range(256)) * 8000  # ~2 MB, bigger than a real response
    raw = codec.encode({"v": 1, "t": "result", "id": 3}, payload)
    header, body, _ = codec.decode(raw)
    assert body == payload


def test_incomplete_buffer_raises_incomplete_not_frameerror():
    """A partial read is normal on a stream socket and must be distinguishable
    from a corrupt frame, or the reader will drop a connection mid-message."""
    raw = codec.encode({"v": 1, "t": "hello"}, b"abcdef")
    for cut in (0, 1, 3, 4, len(raw) - 1):
        with pytest.raises(codec.Incomplete):
            codec.decode(raw[:cut])


def test_decode_reports_bytes_consumed_so_a_stream_can_be_drained():
    a = codec.encode({"v": 1, "t": "hello", "id": 1})
    b = codec.encode({"v": 1, "t": "hello", "id": 2})
    header, _, consumed = codec.decode(a + b)
    assert header["id"] == 1
    assert consumed == len(a)
    header2, _, consumed2 = codec.decode((a + b)[consumed:])
    assert header2["id"] == 2
    assert consumed2 == len(b)


def test_oversized_length_prefix_is_refused_before_allocating():
    """The length prefix is attacker-influenced. Never allocate on it."""
    evil = (codec.MAX_FRAME + 1).to_bytes(4, "big") + b"{}"
    with pytest.raises(codec.FrameError, match="exceeds"):
        codec.decode(evil)


def test_header_without_a_newline_terminator_is_a_frame_error():
    body = b'{"v":1,"t":"hello"}'          # no trailing newline
    raw = len(body).to_bytes(4, "big") + body
    with pytest.raises(codec.FrameError, match="terminator"):
        codec.decode(raw)


def test_malformed_header_json_is_a_frame_error():
    body = b'{"v":1,"t":\n'
    raw = len(body).to_bytes(4, "big") + body
    with pytest.raises(codec.FrameError):
        codec.decode(raw)


def test_nested_header_values_are_refused_on_encode():
    """The Java side parses a FLAT schema. Emitting nesting from Python would
    produce frames it cannot read, and the failure would appear on the far side."""
    with pytest.raises(codec.FrameError, match="flat"):
        codec.encode({"v": 1, "t": "send", "scope": {"include": ["x"]}})
    with pytest.raises(codec.FrameError, match="flat"):
        codec.encode({"v": 1, "t": "send", "methods": ["GET"]})


def test_missing_required_header_fields_are_refused_on_encode():
    with pytest.raises(codec.FrameError, match="v"):
        codec.encode({"t": "hello"})
    with pytest.raises(codec.FrameError, match="t"):
        codec.encode({"v": 1})


def test_frame_reader_reassembles_across_socket_chunks():
    """Stream sockets split writes wherever they like."""
    payload = b"x" * 100_000
    raw = codec.encode({"v": 1, "t": "result", "id": 5}, payload)
    a, b = socket.socketpair()
    try:
        for i in range(0, len(raw), 4096):
            a.sendall(raw[i : i + 4096])
        header, body = codec.FrameReader(b).read()
        assert header["id"] == 5
        assert body == payload
    finally:
        a.close()
        b.close()


def test_frame_reader_handles_coalesced_frames():
    """One recv may deliver several whole frames. A reader that returns after
    the first and drops the rest loses them silently, and the loss surfaces
    later as a misleading "peer closed mid-frame"."""
    a, b = socket.socketpair()
    try:
        a.sendall(b"".join(codec.encode({"v": 1, "t": "hello", "id": i}) for i in (1, 2, 3)))
        reader = codec.FrameReader(b)
        assert [reader.read()[0]["id"] for _ in range(3)] == [1, 2, 3]
    finally:
        a.close()
        b.close()


# ---- config body -------------------------------------------------------

def test_config_body_round_trips_with_repeated_keys():
    pairs = {
        "scope.include": ["https://app.acme.com/*", "https://api.acme.com/*"],
        "scope.exclude": ["*/admin/delete*"],
        "limit.rate_rps": ["5"],
    }
    body = codec.build_config_body(pairs)
    assert codec.parse_config_body(body) == pairs


def test_config_body_preserves_order_of_repeated_keys():
    pairs = {"scope.include": ["a", "b", "c"]}
    assert codec.parse_config_body(codec.build_config_body(pairs))["scope.include"] == ["a", "b", "c"]


def test_config_body_rejects_a_value_containing_a_tab_or_newline():
    """Rejected rather than escaped: an escaping scheme is another parser."""
    with pytest.raises(codec.FrameError, match="tab|newline"):
        codec.build_config_body({"scope.include": ["a\tb"]})
    with pytest.raises(codec.FrameError, match="tab|newline"):
        codec.build_config_body({"scope.include": ["a\nb"]})


def test_config_body_rejects_an_unrecognised_key():
    """Silently ignoring a key the sender believed it set is how a scope rule
    goes missing."""
    with pytest.raises(codec.FrameError, match="unrecognised|unknown"):
        codec.parse_config_body(b"scope.includ\thttps://typo/*\n")


def test_config_body_rejects_a_line_without_a_tab():
    with pytest.raises(codec.FrameError):
        codec.parse_config_body(b"scope.include https://no-tab/*\n")


# ---- golden vectors ----------------------------------------------------

def test_every_vector_round_trips():
    data = json.loads(VECTORS.read_text())
    for v in data["frames"]:
        raw = codec.encode(v["header"], v["body_utf8"].encode("utf-8"))
        header, body, _ = codec.decode(raw)
        assert header == v["header"], v["name"]
        assert body.decode("utf-8") == v["body_utf8"], v["name"]


def test_vectors_match_their_recorded_hex():
    """The Java codec asserts against these same bytes. If Python's output
    drifts from the recorded hex, the two implementations have diverged."""
    data = json.loads(VECTORS.read_text())
    for v in data["frames"]:
        assert v["hex"], f"vector {v['name']} has no recorded hex"
        raw = codec.encode(v["header"], v["body_utf8"].encode("utf-8"))
        assert raw.hex() == v["hex"], v["name"]
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_bridge_codec.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.bridge'`

- [ ] **Step 5: Write the implementation**

```python
# src/hx/bridge/codec.py
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
    except ValueError as exc:          # UnicodeDecodeError is a ValueError
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
```

- [ ] **Step 6: Fill in the golden-vector hex from the implementation**

```bash
.venv/bin/python - <<'PY'
import json
from pathlib import Path
import sys
sys.path.insert(0, "src")
from hx.bridge import codec

p = Path("tests/vectors/frames.json")
data = json.loads(p.read_text())
for v in data["frames"]:
    raw = codec.encode(v["header"], v["body_utf8"].encode("utf-8"))
    if v["hex"] and v["hex"] != raw.hex():
        raise SystemExit(f"vector {v['name']} hex disagrees with the encoder")
    v["hex"] = raw.hex()
p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
print(f"recorded hex for {len(data['frames'])} vectors")
PY
```

The script **refuses to overwrite a non-empty hex that disagrees** — the first vector's hex was written by hand, so this run also checks the implementation against an independently-derived value rather than blessing whatever it produced.

- [ ] **Step 7: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_bridge_codec.py -v`
Expected: PASS, 19 passed

- [ ] **Step 8: Run the whole suite**

Run: `.venv/bin/pytest -q`
Expected: PASS, 131 passed (112 from Plan 1 + 19)

- [ ] **Step 9: Commit**

```bash
git add docs/bridge-protocol.md tests/vectors/frames.json src/hx/bridge tests/test_bridge_codec.py
git commit -m "feat(bridge): frame codec, wire protocol, and shared golden vectors"
```

---

### Task 2: The Java codec, tested against the same vectors

**Files:**
- Create: `extension/src/hx/bridge/Json.java`
- Create: `extension/src/hx/bridge/Frame.java`
- Create: `extension/src/hx/bridge/ConfigBody.java`
- Create: `extension/test/hx/bridge/CodecTest.java`
- Create: `extension/build.sh`
- Create: `extension/test.sh`
- Modify: `.gitignore` — add `extension/build/`

**Interfaces:**
- Consumes: `tests/vectors/frames.json` from Task 1 — the same file, read by the Java test
- Produces:
  - `hx.bridge.Json.write(Map<String,Object>) -> String`
  - `hx.bridge.Json.parse(String) -> Map<String,Object>` — flat only; values become `String`, `Long`, `Boolean` or `null`
  - `hx.bridge.Json.JsonError extends RuntimeException`
  - `hx.bridge.Frame.encode(Map<String,Object> header, byte[] body) -> byte[]`
  - `hx.bridge.Frame.decode(byte[] buf) -> Frame.Decoded` with fields `header`, `body`, `consumed`
  - `hx.bridge.Frame.read(InputStream) -> Frame.Decoded`
  - `hx.bridge.Frame.Incomplete`, `hx.bridge.Frame.FrameError`
  - `hx.bridge.ConfigBody.parse(byte[]) -> Map<String,List<String>>`
  - `hx.bridge.Frame.MAX_FRAME` — `64 * 1024 * 1024`

- [ ] **Step 1: Write the build and test scripts**

```bash
# extension/build.sh
#!/usr/bin/env bash
# Build the hx bridge extension. No Gradle, no Maven, no third-party
# dependencies: this jar enforces scope against client production systems and
# its supply chain is deliberately empty.
set -euo pipefail
cd "$(dirname "$0")"

MONTOYA="${MONTOYA_JAR:-../../burp-lab/probe/lib/montoya-api.jar}"
[ -f "$MONTOYA" ] || { echo "montoya-api.jar not found at $MONTOYA (set MONTOYA_JAR)" >&2; exit 1; }

rm -rf build/classes build/hx-bridge.jar
mkdir -p build/classes
javac --release 21 -nowarn -Xlint:-options \
      -cp "$MONTOYA" -d build/classes \
      $(find src -name '*.java')
printf 'Manifest-Version: 1.0\nImplementation-Title: hx-bridge\n' > build/MANIFEST.MF
jar cfm build/hx-bridge.jar build/MANIFEST.MF -C build/classes .
echo "built $(pwd)/build/hx-bridge.jar"
```

```bash
# extension/test.sh
#!/usr/bin/env bash
# Run the extension's own tests. A tiny hand-rolled runner: adding JUnit would
# mean adding a dependency and a build tool, which is what this design avoids.
set -euo pipefail
cd "$(dirname "$0")"

MONTOYA="${MONTOYA_JAR:-../../burp-lab/probe/lib/montoya-api.jar}"
rm -rf build/test-classes
mkdir -p build/test-classes
javac --release 21 -nowarn -Xlint:-options \
      -cp "$MONTOYA" -d build/test-classes \
      $(find src test -name '*.java')
java -cp "build/test-classes:$MONTOYA" hx.bridge.CodecTest
```

```bash
chmod +x extension/build.sh extension/test.sh
```

- [ ] **Step 2: Write the failing test**

A hand-rolled runner, because JUnit would be a dependency. It must exit non-zero on failure or the script above silently passes.

```java
// extension/test/hx/bridge/CodecTest.java
package hx.bridge;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.ByteArrayInputStream;
import java.util.*;

/** Hand-rolled runner: JUnit would be a dependency, and this jar has none. */
public class CodecTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    static void expectThrows(String what, Class<?> type, Runnable body) {
        try {
            body.run();
            check(what + " (expected " + type.getSimpleName() + ")", false);
        } catch (Throwable t) {
            check(what, type.isInstance(t));
        }
    }

    public static void main(String[] args) throws Exception {
        headerRoundTrip();
        bodyIsVerbatim();
        bodyNewlinesDoNotConfuseTheHeaderSplit();
        incompleteIsDistinctFromCorrupt();
        oversizedLengthIsRefused();
        readReassemblesAcrossChunks();
        configBody();
        goldenVectors();

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    static void headerRoundTrip() {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("v", 1L); h.put("t", "hello"); h.put("pid", 4171L);
        Frame.Decoded d = Frame.decode(Frame.encode(h, new byte[0]));
        check("header round trip", d.header.equals(h) && d.body.length == 0);
    }

    static void bodyIsVerbatim() {
        byte[] payload = "GET / HTTP/1.1\r\nHost: a\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> h = Map.of("v", 1L, "t", "send", "id", 1L);
        Frame.Decoded d = Frame.decode(Frame.encode(h, payload));
        check("body survives verbatim", Arrays.equals(d.body, payload));
    }

    static void bodyNewlinesDoNotConfuseTheHeaderSplit() {
        byte[] payload = "\n\n{\"not\":\"a header\"}\n".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> h = Map.of("v", 1L, "t", "send", "id", 2L);
        Frame.Decoded d = Frame.decode(Frame.encode(h, payload));
        check("header ends at the FIRST newline",
              "send".equals(d.header.get("t")) && Arrays.equals(d.body, payload));
    }

    static void incompleteIsDistinctFromCorrupt() {
        byte[] raw = Frame.encode(Map.of("v", 1L, "t", "hello"), "abcdef".getBytes());
        for (int cut : new int[]{0, 1, 3, 4, raw.length - 1}) {
            byte[] part = Arrays.copyOf(raw, cut);
            expectThrows("partial buffer of " + cut + " raises Incomplete",
                         Frame.Incomplete.class, () -> Frame.decode(part));
        }
    }

    static void oversizedLengthIsRefused() {
        byte[] evil = new byte[6];
        long tooBig = Frame.MAX_FRAME + 1L;
        evil[0] = (byte) (tooBig >>> 24); evil[1] = (byte) (tooBig >>> 16);
        evil[2] = (byte) (tooBig >>> 8);  evil[3] = (byte) tooBig;
        expectThrows("oversized length prefix refused before allocating",
                     Frame.FrameError.class, () -> Frame.decode(evil));
    }

    static void readReassemblesAcrossChunks() throws Exception {
        byte[] payload = new byte[100_000];
        new Random(42).nextBytes(payload);
        byte[] raw = Frame.encode(Map.of("v", 1L, "t", "result", "id", 5L), payload);
        Frame.Decoded d = Frame.read(new ByteArrayInputStream(raw));
        check("read() reassembles a large frame", Arrays.equals(d.body, payload));
    }

    static void configBody() {
        byte[] body = ("scope.include\thttps://a/*\nscope.include\thttps://b/*\n"
                     + "limit.rate_rps\t5\n").getBytes(StandardCharsets.UTF_8);
        Map<String, List<String>> got = ConfigBody.parse(body);
        check("config repeated keys accumulate in order",
              got.get("scope.include").equals(List.of("https://a/*", "https://b/*")));
        check("config single value", got.get("limit.rate_rps").equals(List.of("5")));
        expectThrows("unrecognised config key is an error", Frame.FrameError.class,
                     () -> ConfigBody.parse("scope.includ\tx\n".getBytes(StandardCharsets.UTF_8)));
        expectThrows("config line without a tab is an error", Frame.FrameError.class,
                     () -> ConfigBody.parse("scope.include x\n".getBytes(StandardCharsets.UTF_8)));
    }

    /** The vectors Python recorded. If these disagree, the two codecs have drifted. */
    static void goldenVectors() throws Exception {
        Path p = Path.of("..", "tests", "vectors", "frames.json");
        String text = Files.readString(p, StandardCharsets.UTF_8);
        List<Map<String, Object>> frames = MiniVectorReader.frames(text);
        check("vectors file has frames", !frames.isEmpty());
        for (Map<String, Object> v : frames) {
            String name = (String) v.get("name");
            @SuppressWarnings("unchecked")
            Map<String, Object> header = (Map<String, Object>) v.get("header");
            byte[] body = ((String) v.get("body_utf8")).getBytes(StandardCharsets.UTF_8);
            String wantHex = (String) v.get("hex");

            String gotHex = hex(Frame.encode(header, body));
            check("vector " + name + " encodes to the recorded bytes", gotHex.equals(wantHex));

            Frame.Decoded d = Frame.decode(unhex(wantHex));
            check("vector " + name + " decodes to the recorded header", d.header.equals(header));
            check("vector " + name + " decodes to the recorded body", Arrays.equals(d.body, body));
        }
    }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    static byte[] unhex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
}
```

The vectors file is JSON with one level of nesting, which `Json.parse` deliberately cannot read. Write a 40-line reader for exactly that shape:

```java
// extension/test/hx/bridge/MiniVectorReader.java
package hx.bridge;

import java.util.*;

/**
 * Reads tests/vectors/frames.json. Json.parse handles only flat objects by
 * design, and the vectors file is nested, so the TEST carries its own reader
 * rather than widening the production parser to suit a test.
 */
final class MiniVectorReader {

    static List<Map<String, Object>> frames(String text) {
        List<Map<String, Object>> out = new ArrayList<>();
        int i = text.indexOf("\"frames\"");
        if (i < 0) throw new IllegalArgumentException("no frames key");
        int depth = 0;
        int objStart = -1;
        for (int p = text.indexOf('[', i); p < text.length(); p++) {
            char c = text.charAt(p);
            if (c == '"') { p = skipString(text, p); continue; }
            if (c == '{') { if (depth == 0) objStart = p; depth++; }
            else if (c == '}') {
                depth--;
                if (depth == 0) out.add(Json.parse(text.substring(objStart, p + 1)));
            } else if (c == ']' && depth == 0) break;
        }
        return out;
    }

    private static int skipString(String s, int start) {
        for (int p = start + 1; p < s.length(); p++) {
            if (s.charAt(p) == '\\') { p++; continue; }
            if (s.charAt(p) == '"') return p;
        }
        throw new IllegalArgumentException("unterminated string");
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd extension && ./test.sh`
Expected: FAIL — compilation error, `cannot find symbol: class Frame`

- [ ] **Step 4: Write `Json.java`**

```java
// extension/src/hx/bridge/Json.java
package hx.bridge;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A JSON reader and writer for FLAT objects only.
 *
 * Values may be string, integer, boolean or null -- no nested objects, no
 * arrays. That is not a shortcut, it is the contract: the bridge header schema
 * is flat precisely so this parser stays small enough to be obviously correct,
 * and structured payloads travel in the frame body instead. A nested value is
 * rejected loudly rather than half-parsed.
 */
public final class Json {

    public static class JsonError extends RuntimeException {
        public JsonError(String m) { super(m); }
    }

    private Json() { }

    // ---- writing ----------------------------------------------------

    public static String write(Map<String, Object> obj) {
        StringBuilder s = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : obj.entrySet()) {
            if (!first) s.append(',');
            first = false;
            writeString(s, e.getKey());
            s.append(':');
            writeValue(s, e.getValue());
        }
        return s.append('}').toString();
    }

    private static void writeValue(StringBuilder s, Object v) {
        if (v == null) { s.append("null"); return; }
        if (v instanceof String str) { writeString(s, str); return; }
        if (v instanceof Boolean b) { s.append(b ? "true" : "false"); return; }
        if (v instanceof Integer || v instanceof Long) { s.append(v); return; }
        throw new JsonError("header must be flat; cannot write " + v.getClass().getName());
    }

    private static void writeString(StringBuilder s, String v) {
        s.append('"');
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            switch (c) {
                case '"'  -> s.append("\\\"");
                case '\\' -> s.append("\\\\");
                case '\n' -> s.append("\\n");
                case '\r' -> s.append("\\r");
                case '\t' -> s.append("\\t");
                case '\b' -> s.append("\\b");
                case '\f' -> s.append("\\f");
                default -> {
                    if (c < 0x20) s.append(String.format("\\u%04x", (int) c));
                    else s.append(c);
                }
            }
        }
        s.append('"');
    }

    // ---- parsing ----------------------------------------------------

    public static Map<String, Object> parse(String text) {
        P p = new P(text);
        Map<String, Object> out = parseObject(p);
        p.ws();
        // Python's json.loads raises "Extra data" here. Accepting it would let a
        // crafted frame be valid on one side of the bridge and not the other.
        if (p.i != text.length())
            throw new JsonError("trailing data after the header object at " + p.i);
        return out;
    }

    private static Map<String, Object> parseObject(P p) {
        p.ws();
        p.expect('{');
        Map<String, Object> out = new LinkedHashMap<>();
        p.ws();
        if (p.peek() == '}') { p.next(); return out; }
        while (true) {
            p.ws();
            String key = p.string();
            p.ws();
            p.expect(':');
            p.ws();
            out.put(key, p.value());
            p.ws();
            char c = p.next();
            if (c == '}') return out;
            if (c != ',') throw new JsonError("expected ',' or '}' at " + p.i);
        }
    }

    private static final class P {
        final String s;
        int i = 0;
        P(String s) { this.s = s; }

        char peek() {
            if (i >= s.length()) throw new JsonError("unexpected end of input");
            return s.charAt(i);
        }

        char next() { char c = peek(); i++; return c; }

        void expect(char c) {
            char got = next();
            if (got != c) throw new JsonError("expected '" + c + "' but found '" + got + "' at " + (i - 1));
        }

        void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }

        String string() {
            expect('"');
            StringBuilder b = new StringBuilder();
            while (true) {
                char c = next();
                if (c == '"') return b.toString();
                if (c < 0x20)
                    // RFC 8259 forbids raw control characters in a string, and
                    // Python's json.loads rejects them. Accepting them here
                    // would let a frame be valid on one side of the bridge only.
                    throw new JsonError(
                        String.format("raw control character U+%04X in string", (int) c));
                if (c != '\\') { b.append(c); continue; }
                char esc = next();
                switch (esc) {
                    case '"'  -> b.append('"');
                    case '\\' -> b.append('\\');
                    case '/'  -> b.append('/');
                    case 'n'  -> b.append('\n');
                    case 'r'  -> b.append('\r');
                    case 't'  -> b.append('\t');
                    case 'b'  -> b.append('\b');
                    case 'f'  -> b.append('\f');
                    case 'u'  -> {
                        if (i + 4 > s.length()) throw new JsonError("truncated \\u escape");
                        String hex = s.substring(i, i + 4);
                        for (int k = 0; k < 4; k++) {
                            char hc = hex.charAt(k);
                            boolean isHex = (hc >= '0' && hc <= '9')
                                         || (hc >= 'a' && hc <= 'f') || (hc >= 'A' && hc <= 'F');
                            // Integer.parseInt would throw NumberFormatException, which
                            // escapes Frame.decode's catch of JsonError entirely.
                            if (!isHex) throw new JsonError("bad hex in \\u escape: " + hex);
                        }
                        char u = (char) Integer.parseInt(hex, 16);
                        i += 4;
                        // A supplementary character is legally encoded as a PAIR of
                        // \u escapes, and json.dumps emits exactly that by default
                        // (ensure_ascii=True). Rejecting a high surrogate outright
                        // would refuse spec-legal frames. Only an UNPAIRED surrogate
                        // is invalid -- it survives parsing and Java's UTF-8 encoder
                        // then silently writes it as '?', where Python raises.
                        if (Character.isHighSurrogate(u)) {
                            if (i + 6 > s.length() || s.charAt(i) != '\\' || s.charAt(i + 1) != 'u')
                                throw new JsonError("unpaired high surrogate: " + hex);
                            String lowHex = s.substring(i + 2, i + 6);
                            for (int k = 0; k < 4; k++) {
                                char hc = lowHex.charAt(k);
                                if (!((hc >= '0' && hc <= '9') || (hc >= 'a' && hc <= 'f')
                                        || (hc >= 'A' && hc <= 'F')))
                                    throw new JsonError("bad hex in low surrogate: " + lowHex);
                            }
                            char low = (char) Integer.parseInt(lowHex, 16);
                            if (!Character.isLowSurrogate(low))
                                throw new JsonError("high surrogate not followed by a low one: " + lowHex);
                            b.append(u).append(low);
                            i += 6;
                        } else if (Character.isLowSurrogate(u)) {
                            throw new JsonError("unpaired low surrogate: " + hex);
                        } else {
                            b.append(u);
                        }
                    }
                    default -> throw new JsonError("bad escape \\" + esc);
                }
            }
        }

        Object value() {
            char c = peek();
            if (c == '"') return string();
            if (c == '{' || c == '[')
                throw new JsonError("header must be flat; nested values are not supported");
            if (s.startsWith("true", i))  { i += 4; return Boolean.TRUE; }
            if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
            if (s.startsWith("null", i))  { i += 4; return null; }
            int start = i;
            if (c == '-') i++;
            int digits = i;
            while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            if (i == digits) throw new JsonError("no digits in number at " + start);
            if (i < s.length() && (s.charAt(i) == '.' || s.charAt(i) == 'e' || s.charAt(i) == 'E'))
                throw new JsonError("header numbers must be integers");
            String lit = s.substring(start, i);
            // Python rejects leading zeros; accepting them here would let the two
            // sides disagree on whether a frame is valid.
            if (lit.length() > (lit.startsWith("-") ? 2 : 1)
                    && lit.charAt(lit.startsWith("-") ? 1 : 0) == '0')
                throw new JsonError("leading zeros are not valid JSON: " + lit);
            try {
                // Long.parseLong throws NumberFormatException, which is NOT a
                // JsonError and would escape Frame.decode's catch clause.
                return Long.parseLong(lit);
            } catch (NumberFormatException e) {
                throw new JsonError("integer out of 64-bit range: " + lit);
            }
        }
    }
}
```

- [ ] **Step 5: Write `Frame.java` and `ConfigBody.java`**

```java
// extension/src/hx/bridge/Frame.java
package hx.bridge;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

/** [4-byte BE length][header JSON]\n[body bytes] */
public final class Frame {

    public static final int MAX_FRAME = 64 * 1024 * 1024;

    /** The buffer holds less than one whole frame. Normal on a stream socket. */
    public static class Incomplete extends RuntimeException {
        public Incomplete(String m) { super(m); }
    }

    /** The bytes are not a valid frame. */
    public static class FrameError extends RuntimeException {
        public FrameError(String m) { super(m); }
    }

    public static final class Decoded {
        public final Map<String, Object> header;
        public final byte[] body;
        public final int consumed;
        Decoded(Map<String, Object> header, byte[] body, int consumed) {
            this.header = header; this.body = body; this.consumed = consumed;
        }
    }

    private Frame() { }

    public static byte[] encode(Map<String, Object> header, byte[] body) {
        byte[] head = Json.write(header).getBytes(StandardCharsets.UTF_8);
        int length = head.length + 1 + body.length;
        if (length > MAX_FRAME) throw new FrameError("frame of " + length + " exceeds MAX_FRAME");
        byte[] out = new byte[4 + length];
        out[0] = (byte) (length >>> 24); out[1] = (byte) (length >>> 16);
        out[2] = (byte) (length >>> 8);  out[3] = (byte) length;
        System.arraycopy(head, 0, out, 4, head.length);
        out[4 + head.length] = '\n';
        System.arraycopy(body, 0, out, 5 + head.length, body.length);
        return out;
    }

    public static Decoded decode(byte[] buf) {
        if (buf.length < 4) throw new Incomplete("need a length prefix");
        long length = ((long) (buf[0] & 0xff) << 24) | ((buf[1] & 0xff) << 16)
                    | ((buf[2] & 0xff) << 8) | (buf[3] & 0xff);
        // Checked BEFORE any allocation: the prefix is attacker-influenced.
        if (length > MAX_FRAME) throw new FrameError("declared frame of " + length + " exceeds MAX_FRAME");
        int end = (int) (4 + length);
        if (buf.length < end) throw new Incomplete("need " + end + " bytes, have " + buf.length);

        int nl = -1;
        for (int i = 4; i < end; i++) if (buf[i] == '\n') { nl = i; break; }
        if (nl < 0) throw new FrameError("header has no newline terminator");

        String headerText;
        try {
            // Java's default decoder REPLACES malformed bytes with U+FFFD, silently
            // accepting a frame Python rejects outright. Decode strictly instead.
            headerText = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(buf, 4, nl - 4))
                    .toString();
        } catch (java.nio.charset.CharacterCodingException e) {
            throw new FrameError("header bytes are not valid UTF-8: " + e.getMessage());
        }
        Map<String, Object> header;
        try {
            header = Json.parse(headerText);
        } catch (Json.JsonError e) {
            throw new FrameError("header is not valid JSON: " + e.getMessage());
        }
        return new Decoded(header, Arrays.copyOfRange(buf, nl + 1, end), end);
    }

    /** Read exactly one frame, reassembling across however many chunks arrive. */
    public static Decoded read(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[65536];
        while (true) {
            try {
                return decode(buf.toByteArray());
            } catch (Incomplete ignored) {
                // fall through and read more
            }
            int n = in.read(chunk);
            if (n < 0) throw new Incomplete("peer closed mid-frame");
            buf.write(chunk, 0, n);
        }
    }
}
```

```java
// extension/src/hx/bridge/ConfigBody.java
package hx.bridge;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * The `configure` body: key<TAB>value lines, repeated keys accumulating in
 * order. Not JSON, because a flat JSON parser cannot express the nested scope
 * and limit configuration and widening the parser is the wrong trade.
 */
public final class ConfigBody {

    public static final Set<String> KEYS = Set.of(
        "scope.include", "scope.exclude", "dangerous.path", "method.allow",
        "limit.rate_rps", "limit.concurrency", "limit.max_requests", "render.allow"
    );

    private ConfigBody() { }

    public static Map<String, List<String>> parse(byte[] body) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (String line : new String(body, StandardCharsets.UTF_8).split("\n", -1)) {
            if (line.isEmpty()) continue;
            int tab = line.indexOf('\t');
            if (tab < 0) throw new Frame.FrameError("config line has no tab separator: " + line);
            String key = line.substring(0, tab);
            if (!KEYS.contains(key))
                // Silently ignoring a key the sender believed it set is how a
                // scope rule goes missing.
                throw new Frame.FrameError("unrecognised config key: " + key);
            out.computeIfAbsent(key, k -> new ArrayList<>()).add(line.substring(tab + 1));
        }
        return out;
    }
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd extension && ./test.sh`
Expected: every line `ok`, final line `ALL PASS`, exit 0

- [ ] **Step 7: Verify the build produces a jar**

Run: `cd extension && ./build.sh && unzip -l build/hx-bridge.jar | tail -5`
Expected: `hx/bridge/Json.class`, `Frame.class`, `ConfigBody.class` present

- [ ] **Step 8: Prove the runner actually fails on a failure**

A hand-rolled test runner that cannot fail is worse than no runner. Confirm it before trusting it:

```bash
cd extension
sed -i 's/check("header round trip", d.header.equals(h)/check("header round trip", !d.header.equals(h)/' test/hx/bridge/CodecTest.java
./test.sh; echo "exit=$?"      # expect a FAIL line and exit=1
sed -i 's/check("header round trip", !d.header.equals(h)/check("header round trip", d.header.equals(h)/' test/hx/bridge/CodecTest.java
./test.sh; echo "exit=$?"      # expect ALL PASS and exit=0
```

- [ ] **Step 9: Commit**

```bash
git add extension .gitignore
git commit -m "feat(bridge): zero-dependency Java codec, tested against the shared vectors"
```

---

### Task 3: The Python bridge server

**Files:**
- Create: `src/hx/bridge/server.py`
- Test: `tests/test_bridge_server.py`

**Interfaces:**
- Consumes: `hx.bridge.codec` (Task 1)
- Produces:
  - `hx.bridge.server.BridgeServer(socket_path: Path, engagement_id: str, on_hello=None)`
  - `BridgeServer.start()` / `BridgeServer.stop()`
  - `BridgeServer.socket_path: Path`
  - `BridgeServer.state: str` — `"waiting" | "connected" | "configured" | "halted"`
  - `BridgeServer.config_epoch: int`
  - `BridgeServer.configure(pairs: dict[str, list[str]], scope_sha256: str, profile: str) -> int` — returns the acknowledged epoch
  - `BridgeServer.halt(reason: str)` / `BridgeServer.resume()`
  - `hx.bridge.server.BridgeError(Exception)`
  - `hx.bridge.server.socket_path_for(engagement_id: str) -> Path` — `$XDG_RUNTIME_DIR/hx/<engagement>-<random>.sock`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_bridge_server.py
import os
import socket
import stat
import threading
import time
from pathlib import Path

import pytest

from hx.bridge import codec, server


@pytest.fixture
def srv(tmp_path):
    s = server.BridgeServer(tmp_path / "b.sock", engagement_id="e-1")
    s.start()
    yield s
    s.stop()


def _client(path):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(str(path))
    return c


def test_socket_and_directory_permissions(tmp_path):
    s = server.BridgeServer(tmp_path / "sub" / "b.sock", engagement_id="e-1")
    s.start()
    try:
        assert stat.S_IMODE(s.socket_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(s.socket_path.parent.stat().st_mode) == 0o700
    finally:
        s.stop()


def test_stop_unlinks_the_socket(tmp_path):
    s = server.BridgeServer(tmp_path / "b.sock", engagement_id="e-1")
    s.start()
    path = s.socket_path
    assert path.exists()
    s.stop()
    assert not path.exists()


def test_refuses_to_start_if_the_path_already_exists(tmp_path):
    p = tmp_path / "b.sock"
    p.write_text("squatter")
    s = server.BridgeServer(p, engagement_id="e-1")
    with pytest.raises(server.BridgeError, match="exists"):
        s.start()


def test_socket_path_for_uses_a_fresh_random_basename():
    a = server.socket_path_for("e-1")
    b = server.socket_path_for("e-1")
    assert a != b
    assert "e-1" in a.name and a.name.endswith(".sock")


def test_hello_moves_state_to_connected(srv):
    c = _client(srv.socket_path)
    try:
        c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                                "pid": os.getpid(), "burp_version": "2026.7.3",
                                "instance_id": "i-1", "engagement_id": "e-1"}))
        deadline = time.time() + 5
        while srv.state != "connected" and time.time() < deadline:
            time.sleep(0.01)
        assert srv.state == "connected"
    finally:
        c.close()


def test_engagement_id_mismatch_is_fatal(srv):
    """Client A's traffic must never land in client B's store."""
    c = _client(srv.socket_path)
    try:
        c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                                "pid": os.getpid(), "burp_version": "x",
                                "instance_id": "i-1", "engagement_id": "SOMEONE-ELSE"}))
        assert c.recv(4096) == b"", "server should close the connection"
        assert srv.state == "waiting"
        assert srv.rejected_hellos == 1
    finally:
        c.close()


def test_protocol_version_mismatch_is_fatal(srv):
    c = _client(srv.socket_path)
    try:
        c.sendall(codec.encode({"v": 99, "t": "hello", "engagement_id": "e-1",
                                "ext_version": "0.1", "pid": 1,
                                "burp_version": "x", "instance_id": "i-1"}))
        assert c.recv(4096) == b""
        assert srv.state == "waiting"
    finally:
        c.close()


def test_configure_round_trip_returns_an_epoch(srv):
    c = _client(srv.socket_path)
    try:
        c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1", "pid": 1,
                                "burp_version": "x", "instance_id": "i-1",
                                "engagement_id": "e-1"}))
        result = {}

        def do_configure():
            result["epoch"] = srv.configure(
                {"scope.include": ["https://a/*"], "limit.rate_rps": ["5"]},
                scope_sha256="deadbeef", profile="production",
            )

        t = threading.Thread(target=do_configure)
        t.start()

        header, body = codec.FrameReader(c).read()
        assert header["t"] == "configure"
        assert header["engagement_id"] == "e-1"
        assert header["scope_sha256"] == "deadbeef"
        assert codec.parse_config_body(body)["scope.include"] == ["https://a/*"]

        c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                "config_epoch": 1}))
        t.join(timeout=5)
        assert result["epoch"] == 1
        assert srv.state == "configured"
    finally:
        c.close()


def test_configure_carries_id_and_deadline(srv):
    """Both are required on every request frame by the protocol document."""
    c = _client(srv.socket_path)
    try:
        c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1", "pid": 1,
                                "burp_version": "x", "instance_id": "i-1",
                                "engagement_id": "e-1"}))
        threading.Thread(
            target=lambda: srv.configure({"scope.include": ["https://a/*"]},
                                         scope_sha256="x", profile="production"),
            daemon=True,
        ).start()
        header, _ = codec.FrameReader(c).read()
        assert isinstance(header["id"], int) and header["id"] > 0
        assert isinstance(header["deadline_us"], int)
        assert header["deadline_us"] > time.time_ns() // 1000
    finally:
        c.close()


def test_configure_before_hello_is_refused(srv):
    with pytest.raises(server.BridgeError, match="not connected"):
        srv.configure({"scope.include": ["https://a/*"]}, scope_sha256="x", profile="production")


def test_reconnect_resets_to_deny_all(srv):
    """extensionData does not survive a Burp restart, so a reconnected
    extension is unconfigured no matter what the previous one knew."""
    c = _client(srv.socket_path)
    c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1", "pid": 1,
                            "burp_version": "x", "instance_id": "i-1",
                            "engagement_id": "e-1"}))
    deadline = time.time() + 5
    while srv.state != "connected" and time.time() < deadline:
        time.sleep(0.01)
    # Without this the test passes even when hello handling is completely
    # broken: state never leaves "waiting", so the second poll's precondition
    # is already true. Verified by sabotage.
    assert srv.state == "connected"
    c.close()

    deadline = time.time() + 5
    while srv.state != "waiting" and time.time() < deadline:
        time.sleep(0.01)
    assert srv.state == "waiting", "a dropped connection must return to DENY-ALL"
    assert srv.config_epoch == 0


def test_oversized_frame_from_the_peer_closes_the_connection(srv):
    c = _client(srv.socket_path)
    try:
        c.sendall((codec.MAX_FRAME + 1).to_bytes(4, "big") + b"{}")
        assert c.recv(4096) == b""
    finally:
        c.close()


def test_peer_credentials_are_recorded(srv):
    c = _client(srv.socket_path)
    try:
        c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                                "pid": os.getpid(), "burp_version": "x",
                                "instance_id": "i-1", "engagement_id": "e-1"}))
        deadline = time.time() + 5
        while srv.state != "connected" and time.time() < deadline:
            time.sleep(0.01)
        assert srv.peer_uid == os.getuid()
        assert srv.peer_pid > 0
    finally:
        c.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_bridge_server.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.bridge.server'`

- [ ] **Step 3: Write the implementation**

```python
# src/hx/bridge/server.py
"""The harness end of the bridge.

Python listens and Burp dials in, inverted from the obvious arrangement: the
harness holds the engagement state and outlives Burp, which we measured losing
everything on restart. A Burp restart is therefore a reconnect, not an outage.

DENY-ALL is the initial and terminal state. A freshly connected extension knows
nothing -- extensionData does not survive a Burp restart -- so it stays
unconfigured until a configure frame is acknowledged.
"""
from __future__ import annotations

import os
import secrets
import socket
import struct
import threading
import time
from pathlib import Path

from hx.bridge import codec


class BridgeError(Exception):
    """The bridge cannot start, or was asked to do something out of order."""


def socket_path_for(engagement_id: str) -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return Path(runtime) / "hx" / f"{engagement_id}-{secrets.token_hex(4)}.sock"


class BridgeServer:
    def __init__(self, socket_path: Path, engagement_id: str, on_hello=None):
        self.socket_path = Path(socket_path)
        self.engagement_id = engagement_id
        self.on_hello = on_hello

        self.state = "waiting"
        self.config_epoch = 0
        self.peer_uid: int | None = None
        self.peer_pid: int | None = None
        self.hello: dict | None = None
        self.rejected_hellos = 0

        self._srv: socket.socket | None = None
        self._conn: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._pending: dict[int, threading.Event] = {}
        self._replies: dict[int, dict] = {}
        self._next_id = 0
        self._generation = 0     # bumped per accepted connection; see _reset
        self._lock = threading.Lock()

    # ---- lifecycle ---------------------------------------------------

    def start(self) -> None:
        if self.socket_path.exists():
            raise BridgeError(
                f"socket path already exists: {self.socket_path}. Refusing to "
                "start rather than adopt a path another process may own."
            )
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.socket_path.parent, 0o700)

        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        self._srv.listen(1)
        self._srv.settimeout(0.2)

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stopping.set()
        for s in (self._conn, self._srv):
            try:
                if s:
                    s.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2)
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass

    # ---- accept / read loop -------------------------------------------

    def _accept_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                conn, _ = self._srv.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                return
            try:
                self._serve(conn)
            except Exception:
                # The accept loop is a daemon thread. If it dies the server
                # looks alive and silently never accepts again, so no exception
                # may escape here.
                try:
                    conn.close()
                except OSError:
                    pass

    def _serve(self, conn: socket.socket) -> None:
        with self._lock:
            self._generation += 1
            gen = self._generation
            self._conn = conn
        try:
            creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                    struct.calcsize("3i"))
            pid, uid, _gid = struct.unpack("3i", creds)
            if uid != os.getuid():
                # The socket authenticates a uid, not a program; a different
                # uid has no business here at all.
                return
            self.peer_pid, self.peer_uid = pid, uid

            reader = codec.FrameReader(conn)
            while not self._stopping.is_set():
                header, body = reader.read()
                if not self._handle(header, body):
                    return
        except (codec.PeerClosed, codec.Incomplete, codec.FrameError, OSError):
            return
        finally:
            self._reset(gen)
            try:
                conn.close()
            except OSError:
                pass

    def _reset(self, gen: int | None = None) -> None:
        """Return to DENY-ALL. `gen` guards against a slow teardown of an old
        connection wiping the state of a newer one."""
        with self._lock:
            if gen is not None and gen != self._generation:
                return
            # Advance the generation as well as guarding on it. Without this,
            # the token only detects "a NEW connection superseded an old one" --
            # it cannot detect this same connection resetting between a caller's
            # _request() returning and its commit, so the caller still sees
            # gen == self._generation and clobbers the waiting state.
            self._generation += 1
            self.state = "waiting"
            self.config_epoch = 0
            self._conn = None
            # A waiter blocked on a reply that will now never arrive must not
            # outlive the connection, and a stale reply must not be collected
            # by a future request.
            for ev in self._pending.values():
                ev.set()
            self._pending.clear()
            self._replies.clear()

    def _handle(self, header: dict, body: bytes) -> bool:
        """Return False to close the connection."""
        if header.get("v") != codec.PROTOCOL_VERSION:
            return False

        t = header.get("t")
        if t == "hello":
            if header.get("engagement_id") != self.engagement_id:
                # Client A's traffic must never land in client B's store.
                self.rejected_hellos += 1
                return False
            self.hello = header
            with self._lock:
                self.state = "connected"
                self.config_epoch = 0   # a fresh hello is a fresh session
            if self.on_hello:
                self.on_hello(header)
            return True

        if t == "configured":
            self._deliver(header)
            return True

        if t in ("result", "error", "exchange"):
            self._deliver(header)          # consumed by a later plan
            return True

        return False

    def _deliver(self, header: dict) -> None:
        rid = header.get("id")
        with self._lock:
            ev = self._pending.get(rid)
            if ev is None:
                # Nobody is waiting: the caller timed out, or this is an
                # unsolicited frame. Recording it would leak an entry that
                # nothing ever collects, forever, on a long-lived bridge.
                return
            self._replies[rid] = header
        ev.set()

    # ---- outbound ------------------------------------------------------

    def _send(self, header: dict, body: bytes = b"") -> None:
        conn = self._conn          # snapshot: the accept thread may null it
        if conn is None:
            raise BridgeError("not connected")
        try:
            conn.sendall(codec.encode(header, body))
        except OSError as exc:
            raise BridgeError(f"send failed: {exc}") from exc

    def _request(self, header: dict, body: bytes = b"", timeout: float = 10.0) -> dict:
        with self._lock:
            self._next_id += 1
            rid = self._next_id
            ev = threading.Event()
            self._pending[rid] = ev
        # deadline_us is set on every request frame from the start so the frame
        # shape never changes later. Acting on it -- abandoning work past the
        # deadline -- belongs to the send path in Plan 3; here it is carried and
        # validated, not enforced.
        header = {**header, "id": rid,
                  "deadline_us": (time.time_ns() // 1000) + int(timeout * 1_000_000)}
        self._send(header, body)
        if not ev.wait(timeout):
            with self._lock:
                self._pending.pop(rid, None)
            raise BridgeError(f"no reply to {header['t']} within {timeout}s")
        with self._lock:
            self._pending.pop(rid, None)
            return self._replies.pop(rid)

    def configure(self, pairs: dict[str, list[str]], scope_sha256: str,
                  profile: str) -> int:
        if self.state not in ("connected", "configured", "halted"):
            raise BridgeError("not connected: cannot configure before hello")
        gen = self._generation
        reply = self._request(
            {
                "v": codec.PROTOCOL_VERSION,
                "t": "configure",
                "engagement_id": self.engagement_id,
                "scope_sha256": scope_sha256,
                "profile": profile,
            },
            codec.build_config_body(pairs),
        )
        if "config_epoch" not in reply:
            raise BridgeError("peer acknowledged configure without a config_epoch")
        with self._lock:
            # Commit only if this is still the same connection. Without the
            # guard, a peer that acks and immediately disconnects leaves
            # state="configured" with no peer attached -- reproduced 59/60.
            if gen != self._generation or self._conn is None:
                raise BridgeError("peer disconnected before configure completed")
            self.config_epoch = int(reply["config_epoch"])
            self.state = "configured"
        return self.config_epoch

    def halt(self, reason: str) -> None:
        self._send({"v": codec.PROTOCOL_VERSION, "t": "halt", "reason": reason})
        self.state = "halted"

    def resume(self) -> None:
        self._send({"v": codec.PROTOCOL_VERSION, "t": "resume"})
        self.state = "configured" if self.config_epoch else "connected"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_bridge_server.py -v`
Expected: PASS, 13 passed

- [ ] **Step 5: Commit**

```bash
git add src/hx/bridge/server.py tests/test_bridge_server.py
git commit -m "feat(bridge): unix socket server with peercred check and deny-all handshake"
```

---

### Task 4: The Java extension — dial, hello, deny-all

**Files:**
- Create: `extension/src/hx/bridge/BridgeClient.java`
- Create: `extension/src/hx/HxExtension.java`
- Create: `extension/test/hx/bridge/BridgeClientTest.java`
- Create: `extension/test/hx/bridge/FakeMontoya.java`
- Modify: `extension/test.sh` — run both test classes

**Interfaces:**
- Consumes: `hx.bridge.Frame`, `hx.bridge.Json`, `hx.bridge.ConfigBody` (Task 2)
- Produces:
  - `hx.bridge.BridgeClient(Path socketPath, String engagementId, String instanceId, Logger log)`
  - `BridgeClient.connect()` / `BridgeClient.close()`
  - `BridgeClient.isConfigured() -> boolean`
  - `BridgeClient.maySend() -> boolean` — configured and not halted
  - `BridgeClient.configEpoch() -> long`
  - `BridgeClient.scopeConfig() -> Map<String,List<String>>`
  - `BridgeClient.checkMaySend() -> void` — throws `NotConfigured` unless configured and not halted
  - `hx.bridge.BridgeClient.NotConfigured extends RuntimeException`
  - `hx.HxExtension implements BurpExtension`

- [ ] **Step 1: Write the fake and the failing test**

```java
// extension/test/hx/bridge/FakeMontoya.java
package hx.bridge;

/**
 * The few Montoya surfaces the bridge touches. MontoyaApi is an interface with
 * 21 sub-interfaces; faking all of it would be a project. The bridge needs
 * logging and a version string, so that is what this provides.
 */
public final class FakeMontoya {

    public static final class Logger {
        public final StringBuilder out = new StringBuilder();
        public final StringBuilder err = new StringBuilder();
        public void info(String s) { out.append(s).append('\n'); }
        public void error(String s) { err.append(s).append('\n'); }
        public boolean sawInfo(String needle) { return out.toString().contains(needle); }
        public boolean sawError(String needle) { return err.toString().contains(needle); }
    }
}
```

```java
// extension/test/hx/bridge/BridgeClientTest.java
package hx.bridge;

import java.io.*;
import java.net.*;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.*;
import java.util.*;

/** Drives BridgeClient against a fake Python server on a real unix socket. */
public class BridgeClientTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("hxbridge");
        Path sock = dir.resolve("t.sock");

        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(sock));

            FakeMontoya.Logger log = new FakeMontoya.Logger();
            BridgeClient client = new BridgeClient(sock, "e-1", "i-1", log);

            Thread t = new Thread(() -> { try { client.connect(); } catch (Exception ignored) { } });
            t.start();

            try (SocketChannel peer = server.accept()) {
                InputStream in = java.nio.channels.Channels.newInputStream(peer);
                OutputStream out = java.nio.channels.Channels.newOutputStream(peer);

                // 1. hello arrives with the right identity
                Frame.Decoded hello = Frame.read(in);
                check("sends hello", "hello".equals(hello.header.get("t")));
                check("hello carries engagement_id", "e-1".equals(hello.header.get("engagement_id")));
                check("hello carries instance_id", "i-1".equals(hello.header.get("instance_id")));
                check("hello carries protocol version", Long.valueOf(1L).equals(hello.header.get("v")));

                // 2. DENY-ALL before configure
                check("unconfigured after hello", !client.isConfigured());
                boolean threw = false;
                try { client.checkMaySend(); } catch (BridgeClient.NotConfigured e) { threw = true; }
                check("checkMaySend throws NotConfigured before configure", threw);

                // 3. configure -> configured, with an epoch
                Map<String, Object> cfg = new LinkedHashMap<>();
                cfg.put("v", 1L); cfg.put("t", "configure"); cfg.put("id", 1L);
                cfg.put("engagement_id", "e-1"); cfg.put("scope_sha256", "abc");
                cfg.put("profile", "production");
                out.write(Frame.encode(cfg, "scope.include\thttps://a/*\nlimit.rate_rps\t5\n"
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8)));
                out.flush();

                Frame.Decoded ack = Frame.read(in);
                check("acks with configured", "configured".equals(ack.header.get("t")));
                check("ack echoes the request id", Long.valueOf(1L).equals(ack.header.get("id")));
                check("ack carries a non-zero epoch",
                      ((Long) ack.header.get("config_epoch")) > 0);

                waitUntil(() -> client.isConfigured());
                check("configured after ack", client.isConfigured());
                check("scope config parsed",
                      client.scopeConfig().get("scope.include").equals(List.of("https://a/*")));
                client.checkMaySend();   // must not throw now

                // 4. halt / resume
                Map<String, Object> halt = Map.of("v", 1L, "t", "halt", "reason", "operator");
                out.write(Frame.encode(halt, new byte[0])); out.flush();
                waitUntil(() -> !client.maySend());
                boolean haltedThrew = false;
                try { client.checkMaySend(); } catch (BridgeClient.NotConfigured e) { haltedThrew = true; }
                check("halt blocks sending", haltedThrew);

                out.write(Frame.encode(Map.of("v", 1L, "t", "resume"), new byte[0])); out.flush();
                waitUntil(() -> client.maySend());
                client.checkMaySend();
                check("resume unblocks sending", true);

                // 5. an engagement_id mismatch on configure is refused
                Map<String, Object> wrong = new LinkedHashMap<>(cfg);
                wrong.put("id", 2L); wrong.put("engagement_id", "SOMEONE-ELSE");
                out.write(Frame.encode(wrong, new byte[0])); out.flush();
                Frame.Decoded err = Frame.read(in);
                check("engagement mismatch answered with error",
                      "error".equals(err.header.get("t")));
                check("error class names the mismatch",
                      String.valueOf(err.header.get("class")).contains("engagement"));
            }
            client.close();
        } finally {
            Files.deleteIfExists(sock);
            Files.deleteIfExists(dir);
        }

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    interface Cond { boolean ok(); }

    static void waitUntil(Cond c) throws Exception {
        long end = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < end) {
            if (c.ok()) return;
            Thread.sleep(10);
        }
    }
}
```

Update `extension/test.sh` to run both classes:

```bash
java -cp "build/test-classes:$MONTOYA" hx.bridge.CodecTest
java -cp "build/test-classes:$MONTOYA" hx.bridge.BridgeClientTest
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd extension && ./test.sh`
Expected: FAIL — `cannot find symbol: class BridgeClient`

- [ ] **Step 3: Write `BridgeClient.java`**

```java
// extension/src/hx/bridge/BridgeClient.java
package hx.bridge;

import java.io.*;
import java.net.*;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The Burp end of the bridge. Dials the harness, announces itself, and refuses
 * to send anything until it has been configured.
 *
 * DENY-ALL is the initial and terminal state. Burp's extensionData does not
 * survive a restart, so a reconnected extension knows nothing -- it must be
 * told the scope again before it may issue a single request.
 */
public final class BridgeClient {

    public static final long PROTOCOL_VERSION = 1L;

    public static class NotConfigured extends RuntimeException {
        public NotConfigured(String m) { super(m); }
    }

    private final Path socketPath;
    private final String engagementId;
    private final String instanceId;
    private final Object log;

    private SocketChannel channel;
    private InputStream in;
    private OutputStream out;

    private final AtomicBoolean configured = new AtomicBoolean(false);
    private final AtomicBoolean halted = new AtomicBoolean(false);
    private volatile long configEpoch = 0;
    private volatile Map<String, List<String>> scopeConfig = Map.of();
    private volatile String haltReason = null;
    private long epochCounter = 0;

    public BridgeClient(Path socketPath, String engagementId, String instanceId, Object log) {
        this.socketPath = socketPath;
        this.engagementId = engagementId;
        this.instanceId = instanceId;
        this.log = log;
    }

    public boolean isConfigured() { return configured.get(); }
    public long configEpoch() { return configEpoch; }
    public Map<String, List<String>> scopeConfig() { return scopeConfig; }
    public boolean maySend() { return configured.get() && !halted.get(); }

    /** Throws unless the extension is configured and not halted. */
    public void checkMaySend() {
        if (!configured.get())
            throw new NotConfigured("not_configured: no configure frame acknowledged yet");
        if (halted.get())
            throw new NotConfigured("halted: " + haltReason);
    }

    public void connect() throws IOException {
        channel = SocketChannel.open(UnixDomainSocketAddress.of(socketPath));
        in = Channels.newInputStream(channel);
        out = Channels.newOutputStream(channel);

        Map<String, Object> hello = new LinkedHashMap<>();
        hello.put("v", PROTOCOL_VERSION);
        hello.put("t", "hello");
        hello.put("ext_version", "0.1.0");
        hello.put("pid", ProcessHandle.current().pid());
        hello.put("burp_version", System.getProperty("hx.burp.version", "unknown"));
        hello.put("instance_id", instanceId);
        hello.put("engagement_id", engagementId);
        send(hello, new byte[0]);

        readLoop();
    }

    private void readLoop() {
        try {
            while (true) {
                Frame.Decoded f = Frame.read(in);
                if (!handle(f)) return;
            }
        } catch (Frame.Incomplete | IOException e) {
            // Peer closed. DENY-ALL is also the terminal state.
            configured.set(false);
            configEpoch = 0;
        } catch (Frame.FrameError e) {
            configured.set(false);
        }
    }

    private boolean handle(Frame.Decoded f) throws IOException {
        Object v = f.header.get("v");
        if (!Long.valueOf(PROTOCOL_VERSION).equals(v)) {
            error(f, "protocol_mismatch", "expected v=" + PROTOCOL_VERSION + " got " + v);
            return false;
        }
        String t = String.valueOf(f.header.get("t"));

        switch (t) {
            case "configure" -> {
                if (!(f.header.get("deadline_us") instanceof Long)) {
                    // Required on every request frame. Missing it means the
                    // sender is not speaking this protocol version properly.
                    error(f, "bad_frame", "request frame has no deadline_us");
                    return true;
                }
                if (!engagementId.equals(f.header.get("engagement_id"))) {
                    error(f, "engagement_mismatch",
                          "configure names engagement " + f.header.get("engagement_id")
                          + " but this extension serves " + engagementId);
                    return true;
                }
                try {
                    scopeConfig = ConfigBody.parse(f.body);
                } catch (Frame.FrameError e) {
                    error(f, "bad_config", e.getMessage());
                    return true;
                }
                configEpoch = ++epochCounter;
                configured.set(true);
                halted.set(false);

                Map<String, Object> ack = new LinkedHashMap<>();
                ack.put("v", PROTOCOL_VERSION);
                ack.put("t", "configured");
                ack.put("id", f.header.get("id"));
                ack.put("config_epoch", configEpoch);
                send(ack, new byte[0]);
            }
            case "halt" -> {
                halted.set(true);
                haltReason = String.valueOf(f.header.get("reason"));
            }
            case "resume" -> halted.set(false);
            default -> {
                error(f, "unknown_frame", "unrecognised frame type " + t);
            }
        }
        return true;
    }

    private void error(Frame.Decoded f, String cls, String detail) throws IOException {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("v", PROTOCOL_VERSION);
        e.put("t", "error");
        e.put("id", f.header.get("id"));
        e.put("class", cls);
        e.put("detail", detail);
        send(e, new byte[0]);
    }

    private synchronized void send(Map<String, Object> header, byte[] body) throws IOException {
        out.write(Frame.encode(header, body));
        out.flush();
    }

    public void close() {
        configured.set(false);
        try { if (channel != null) channel.close(); } catch (IOException ignored) { }
    }
}
```

- [ ] **Step 4: Write `HxExtension.java`**

```java
// extension/src/hx/HxExtension.java
package hx;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import hx.bridge.BridgeClient;

import java.nio.file.Path;

/**
 * Burp entry point. Reads its socket path, engagement id and instance id from
 * system properties so the harness controls them at launch, then dials in on a
 * background thread and stays in DENY-ALL until configured.
 */
public class HxExtension implements BurpExtension {

    private BridgeClient client;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("hx bridge");

        String sock = System.getProperty("hx.socket");
        String engagement = System.getProperty("hx.engagement");
        String instance = System.getProperty("hx.instance", "unknown");

        if (sock == null || engagement == null) {
            api.logging().logToError(
                "hx: -Dhx.socket and -Dhx.engagement are required; extension idle");
            return;
        }
        System.setProperty("hx.burp.version", api.burpSuite().version().toString());

        client = new BridgeClient(Path.of(sock), engagement, instance, api.logging());
        Thread t = new Thread(() -> {
            try {
                client.connect();
            } catch (Exception e) {
                api.logging().logToError("hx: bridge connect failed: " + e);
            }
        }, "hx-bridge");
        t.setDaemon(true);
        t.start();

        api.extension().registerUnloadingHandler(() -> {
            if (client != null) client.close();
        });
        api.logging().logToOutput("hx: bridge dialling " + sock);
    }
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd extension && ./test.sh`
Expected: both classes print `ALL PASS`, exit 0

- [ ] **Step 6: Commit**

```bash
git add extension
git commit -m "feat(bridge): java client dials in, stays deny-all until configured"
```

---

### Task 5: End-to-end against real headless Burp

**Files:**
- Create: `tests/__init__.py` — **required**: without it `from tests.integration import ...` fails with `ModuleNotFoundError: No module named 'tests'`, verified
- Create: `tests/integration/__init__.py`
- Create: `tests/integration/test_real_burp.py`
- Create: `tests/integration/burp_fixture.py`
- Modify: `pyproject.toml` — register the `integration` marker

**Interfaces:**
- Consumes: `hx.bridge.server.BridgeServer`, `extension/build/hx-bridge.jar`
- Produces:
  - `tests.integration.burp_fixture.burp_available() -> bool`
  - `tests.integration.burp_fixture.launch_burp(socket_path, engagement_id) -> subprocess.Popen`

- [ ] **Step 1: Register the marker so the slow test is opt-in**

```toml
# add to pyproject.toml
[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
markers = [
    "integration: loads a real headless Burp Suite; slow (~40s) and needs the jar",
]
addopts = "-m 'not integration'"
```

`addopts` keeps the fast suite fast by default. The integration test runs with `pytest -m integration`.

- [ ] **Step 2: Write the fixture**

```python
# tests/integration/burp_fixture.py
"""Launch a real headless Burp Suite Community with the hx extension loaded.

Everything here was established empirically during the research phase:
  - Burp asks for a licence key on stdin; a bare newline selects Community.
  - The EULA gate is a single Java Preferences key, burp.eula.
  - Launching with -cp instead of -jar means the jar manifest's Add-Opens is
    ignored, so every --add-opens must be repeated on the command line.
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

LAB = Path(os.environ.get("HX_BURP_LAB", Path.home() / "F0RT1KA" / "burp-lab"))
BURP_JAR = LAB / "burpsuite_desktop_v2026.7.3.jar"
BURP_HOME = LAB / "burphome"
EXT_JAR = Path(__file__).resolve().parents[2] / "extension" / "build" / "hx-bridge.jar"

ADD_OPENS = [
    "--add-opens", "java.base/java.lang=ALL-UNNAMED",
    "--add-opens", "java.desktop/javax.swing=ALL-UNNAMED",
    "--add-opens", "java.desktop/java.awt=ALL-UNNAMED",
    "--add-opens", "java.desktop/java.awt.color=ALL-UNNAMED",
    "--add-opens", "java.base/javax.crypto=ALL-UNNAMED",
    "--add-opens", "jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED",
]


def burp_available() -> bool:
    return BURP_JAR.exists() and EXT_JAR.exists()


def launch_burp(socket_path: Path, engagement_id: str) -> subprocess.Popen:
    cmd = [
        "java",
        "-Djava.awt.headless=true",
        f"-Duser.home={BURP_HOME}",
        f"-Dhx.socket={socket_path}",
        f"-Dhx.engagement={engagement_id}",
        "-Dhx.instance=integration",
        *ADD_OPENS,
        "-cp", f"{BURP_JAR}:{EXT_JAR}",
        "burp.StartBurp",
        "--developer-extension-class-name=hx.HxExtension",
        "--disable-auto-update",
    ]
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, cwd=LAB,
    )
    proc.stdin.write(b"\n\n")     # bare newline selects Community Edition
    proc.stdin.flush()
    return proc


def wait_for(predicate, timeout: float = 90.0, interval: float = 0.5) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(interval)
    return False
```

- [ ] **Step 3: Write the failing test**

```python
# tests/integration/test_real_burp.py
import hashlib

import pytest

from hx.bridge import server
from tests.integration import burp_fixture as bf

pytestmark = pytest.mark.integration


@pytest.mark.skipif(not bf.burp_available(),
                    reason="Burp jar or extension jar not built")
def test_real_burp_dials_in_and_handshakes(tmp_path):
    """The whole point of this plan, proved against the real container.

    Fakes prove the logic; only this proves Burp actually loads the extension
    and that the socket handshake works end to end.
    """
    srv = server.BridgeServer(tmp_path / "hx.sock", engagement_id="e-integration")
    srv.start()
    proc = None
    try:
        proc = bf.launch_burp(srv.socket_path, "e-integration")

        assert bf.wait_for(lambda: srv.state == "connected"), \
            "Burp never completed the hello handshake"

        assert srv.hello["engagement_id"] == "e-integration"
        assert srv.hello["instance_id"] == "integration"
        assert "2026" in srv.hello["burp_version"], srv.hello
        assert srv.peer_uid is not None

        pairs = {"scope.include": ["https://app.example.test/*"],
                 "limit.rate_rps": ["5"]}
        epoch = srv.configure(
            pairs,
            scope_sha256=hashlib.sha256(b"x").hexdigest(),
            profile="production",
        )
        assert epoch == 1
        assert srv.state == "configured"
    finally:
        if proc:
            proc.kill()
            proc.wait(timeout=15)
        srv.stop()


@pytest.mark.skipif(not bf.burp_available(),
                    reason="Burp jar or extension jar not built")
def test_burp_restart_returns_the_bridge_to_deny_all(tmp_path):
    """A Burp restart is a reconnect, not an outage -- and the reconnected
    extension knows nothing, because extensionData does not survive."""
    srv = server.BridgeServer(tmp_path / "hx.sock", engagement_id="e-restart")
    srv.start()
    try:
        proc = bf.launch_burp(srv.socket_path, "e-restart")
        assert bf.wait_for(lambda: srv.state == "connected")
        srv.configure({"scope.include": ["https://a/*"]},
                      scope_sha256="abc", profile="production")
        assert srv.state == "configured"

        proc.kill()
        proc.wait(timeout=15)
        assert bf.wait_for(lambda: srv.state == "waiting", timeout=30), \
            "dropped connection must return the bridge to DENY-ALL"
        assert srv.config_epoch == 0
    finally:
        srv.stop()
```

- [ ] **Step 4: Build the extension and run the integration test**

```bash
cd extension && ./build.sh && cd ..
.venv/bin/pytest -m integration tests/integration -v
```

Expected: 2 passed, roughly 60–120 seconds total.

If Burp never connects, read the launch output — the fixture merges stderr into stdout — and check the two failure modes established during research: the EULA prompt (needs `burp.eula` pre-accepted in `$BURP_HOME/.java/.userPrefs/burp/prefs.xml`) and the licence prompt (needs the bare newline the fixture already writes).

- [ ] **Step 5: Confirm the fast suite is still fast**

Run: `time .venv/bin/pytest -q`
Expected: PASS, 144 passed, under 2 seconds — the integration tests excluded by `addopts`.

- [ ] **Step 6: Commit**

```bash
git add tests/__init__.py tests/integration pyproject.toml
git commit -m "test(bridge): real headless Burp completes the handshake end to end"
```

---

## Self-review

**Spec coverage.** §6 framing → Task 1 and 2. §6 socket path, permissions, `SO_PEERCRED`, refuse-if-exists → Task 3. §6 `hello`, `configure`, `config_epoch`, engagement mismatch fatal → Tasks 3 and 4. §6 `halt`/`resume` → Task 4. §4 DENY-ALL as initial and terminal state → Tasks 3 and 4, with the reconnect case tested on both sides. §6 max frame size → Tasks 1 and 2.

**Deliberately out of this plan**, in the plans that follow: `send`/`result`/`error` request flow and the enforcement chain (scope, method allowlist, dangerous paths, rate limit, budgets) — Plan 3; `exchange` push, backpressure classes and credential redaction — Plan 4; identity and liveness — Plan 5. The frame types are documented in `docs/bridge-protocol.md` now so the two codecs do not need changing later, but nothing implements them yet.

**Cross-implementation drift** is the risk this plan is shaped around. One wire-format document, one vector file, and both codecs tested against it — with the Java test asserting the exact bytes Python recorded, so a change on either side that the other does not follow fails immediately rather than at integration.

**Known gap accepted:** `BridgeServer` handles one connection at a time, which matches one Burp per engagement. A second connection attempt while one is live is accepted then dropped by `_serve` returning; that is adequate for now and becomes a real question only if the harness ever supervises several Burps.

---

## Execution handoff

Plan complete. Two execution options:

1. **Subagent-Driven (recommended)** — a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — execute tasks in this session with checkpoints.
