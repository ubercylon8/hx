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
import re
import socket
from pathlib import Path

import pytest

from hx.bridge import codec

VECTORS = Path(__file__).parent / "vectors" / "frames.json"
MALFORMED = Path(__file__).parent / "vectors" / "malformed.json"


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


def test_frame_of_exactly_max_frame_bytes_succeeds():
    """A frame at the boundary should succeed; only MAX_FRAME+1 should fail."""
    # Create a frame that is exactly MAX_FRAME bytes (header + body, not including length prefix)
    header = {"v": 1, "t": "send"}
    # Calculate body size to reach exactly MAX_FRAME
    header_json = b'{"v":1,"t":"send"}'
    header_with_newline = header_json + b"\n"
    payload_size = codec.MAX_FRAME - len(header_with_newline)
    body = b"x" * payload_size
    raw = codec.encode(header, body)
    # Verify it succeeds
    decoded_header, decoded_body, _ = codec.decode(raw)
    assert decoded_header == header
    assert decoded_body == body


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


def test_flat_header_validated_on_decode():
    """The flat restriction is validated on receipt too, not only on send.
    This defends against a peer that ignores the contract."""
    # Nested object
    bad = b'{"v":1,"t":"send","scope":{"include":["x"]}}\n'
    raw = len(bad).to_bytes(4, "big") + bad
    with pytest.raises(codec.FrameError, match="flat"):
        codec.decode(raw)
    # Array
    bad = b'{"v":1,"t":"send","methods":["GET"]}\n'
    raw = len(bad).to_bytes(4, "big") + bad
    with pytest.raises(codec.FrameError, match="flat"):
        codec.decode(raw)


def test_missing_required_header_fields_on_decode():
    """Missing v or t is an error on decode, defending against malformed peers."""
    # Missing v
    bad = b'{"t":"send"}\n'
    raw = len(bad).to_bytes(4, "big") + bad
    with pytest.raises(codec.FrameError, match="v"):
        codec.decode(raw)
    # Missing t
    bad = b'{"v":1}\n'
    raw = len(bad).to_bytes(4, "big") + bad
    with pytest.raises(codec.FrameError, match="t"):
        codec.decode(raw)


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
        reader = codec.FrameReader(b)
        header, body = reader.read()
        assert header["id"] == 5
        assert body == payload
    finally:
        a.close()
        b.close()


def test_frame_reader_handles_coalesced_frames():
    """Regression guard: two frames written in one sendall must be read separately.
    The kernel may coalesce them; the reader must buffer and return them one at a time."""
    f1 = codec.encode({"v": 1, "t": "hello", "id": 1})
    f2 = codec.encode({"v": 1, "t": "hello", "id": 2})
    f3 = codec.encode({"v": 1, "t": "hello", "id": 3})
    a, b = socket.socketpair()
    try:
        a.sendall(f1 + f2 + f3)  # all three in one write
        reader = codec.FrameReader(b)
        header1, _ = reader.read()
        assert header1["id"] == 1
        header2, _ = reader.read()
        assert header2["id"] == 2
        header3, _ = reader.read()
        assert header3["id"] == 3
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


# ---- identity body ------------------------------------------------------

def test_the_identity_frame_round_trips():
    body = codec.identity_body("user", 2, "Cookie", "session=abc",
                               ("https://app.test",))
    out = codec.parse_identity(body)
    assert out["identity_id"] == "user" and out["generation"] == 2
    assert out["inject"] == {"header": "Cookie", "value": "session=abc"}
    assert out["origins"] == ["https://app.test"]


def test_identity_body_carries_more_than_one_origin_in_order():
    body = codec.identity_body("user", 1, "Cookie", "v",
                               ("https://a.test", "https://b.test"))
    assert codec.parse_identity(body)["origins"] == \
        ["https://a.test", "https://b.test"]


@pytest.mark.parametrize("generation", [0, -1, -100])
def test_an_identity_frame_with_a_non_positive_generation_is_refused(generation):
    # Generation is monotonic on the extension side. A zero or negative one
    # could never be above what is held, so it is a malformed frame here
    # rather than a refusal there.
    with pytest.raises(codec.FrameError, match="generation"):
        codec.identity_body("user", generation, "Cookie", "v",
                            ("https://app.test",))


def test_an_identity_frame_with_a_bool_generation_is_refused():
    """`isinstance(True, int)` is True in Python; a bool must not sneak past
    the integer check the way it does not sneak past the header check in
    `_check_header`."""
    with pytest.raises(codec.FrameError, match="generation"):
        codec.identity_body("user", True, "Cookie", "v", ("https://app.test",))


def test_an_identity_frame_with_no_identity_id_is_refused():
    with pytest.raises(codec.FrameError, match="identity_id"):
        codec.identity_body("", 1, "Cookie", "v", ("https://app.test",))


def test_an_identity_frame_with_no_value_is_refused():
    with pytest.raises(codec.FrameError, match="value"):
        codec.identity_body("user", 1, "Cookie", "", ("https://app.test",))


def test_an_identity_frame_with_no_origins_is_refused():
    """An identity with no origin could be applied to any host the scope
    allows -- the same rule the extension-side registry enforces."""
    with pytest.raises(codec.FrameError, match="origin"):
        codec.identity_body("user", 1, "Cookie", "v", ())


def test_parse_identity_rejects_a_body_that_is_not_json():
    with pytest.raises(codec.FrameError):
        codec.parse_identity(b"not json")


def test_parse_identity_rejects_a_missing_generation():
    body = json.dumps({"identity_id": "user",
                       "inject": {"header": "Cookie", "value": "v"},
                       "origins": ["https://app.test"]}).encode("utf-8")
    with pytest.raises(codec.FrameError, match="generation"):
        codec.parse_identity(body)


def test_parse_identity_rejects_a_stale_non_positive_generation_too():
    """Re-validated on the reading side rather than trusted from the writer
    -- the same discipline `parse_config_body` already follows -- so a body
    that skipped `identity_body`'s own check is still caught here."""
    body = json.dumps({"identity_id": "user", "generation": 0,
                       "inject": {"header": "Cookie", "value": "v"},
                       "origins": ["https://app.test"]}).encode("utf-8")
    with pytest.raises(codec.FrameError, match="generation"):
        codec.parse_identity(body)


def test_parse_identity_rejects_empty_origins():
    body = json.dumps({"identity_id": "user", "generation": 1,
                       "inject": {"header": "Cookie", "value": "v"},
                       "origins": []}).encode("utf-8")
    with pytest.raises(codec.FrameError, match="origin"):
        codec.parse_identity(body)


def test_parse_identity_rejects_a_blank_value():
    body = json.dumps({"identity_id": "user", "generation": 1,
                       "inject": {"header": "Cookie", "value": ""},
                       "origins": ["https://app.test"]}).encode("utf-8")
    with pytest.raises(codec.FrameError, match="value"):
        codec.parse_identity(body)


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


# ---- malformed input parity --------------------------------------------
#
# The golden vectors above are all well-formed, which is exactly why probing
# found the Java and Python codecs disagreeing on five of six hostile inputs
# (plan fix f8d8229) with none of these tests noticing. Well-formed vectors
# pin agreement on what is valid; they say nothing about whether both sides
# reject the same invalid input the same way. This suite pins rejection too,
# against the SAME cases the Java CodecTest runs.

def test_every_malformed_case_is_rejected_by_decode():
    data = json.loads(MALFORMED.read_text())
    assert data["cases"], "malformed vectors file has no cases"
    for c in data["cases"]:
        head = c["header_text"].encode("utf-8")
        raw = len(head + b"\n").to_bytes(4, "big") + head + b"\n"
        with pytest.raises(codec.FrameError) as exc:
            codec.decode(raw)
        # Rejected is not enough: it has to be rejected by the rule the case
        # exists to pin. Every case carried only the key "a", so
        # _check_header's required-field rule fired first and five of them --
        # integer_beyond_int64, lone_surrogate, nested_object,
        # unpaired_low_surrogate, high_surrogate_not_followed_by_escape --
        # never reached their own rule at all. Deleting the unpaired-surrogate
        # check in codec.py outright still left the suite at 179 passed. The
        # \"v\":1,\"t\":\"x\" prefix in the vectors file is what fixed that,
        # and this assertion is what stops it being stripped again.
        assert "missing required field" not in str(exc.value), (
            f"{c['name']} is being rejected for a missing required field, not by "
            f"the rule it exists to pin ({str(exc.value)!r}). Restore the "
            f'\'"v":1,"t":"x",\' prefix in {MALFORMED.name}.'
        )


def test_encode_refuses_an_integer_outside_signed_64_bit_range():
    """This diverges the other way from most findings in f8d8229: Python's
    ints are unbounded, so nothing stopped it from emitting a header the Java
    side cannot represent -- a frame valid here and a hard error there."""
    too_big = 2 ** 63
    too_small = -(2 ** 63) - 1
    with pytest.raises(codec.FrameError, match="64-bit"):
        codec.encode({"v": 1, "t": "send", "deadline_us": too_big})
    with pytest.raises(codec.FrameError, match="64-bit"):
        codec.encode({"v": 1, "t": "send", "deadline_us": too_small})
    # The boundary values themselves must still be accepted.
    codec.encode({"v": 1, "t": "send", "deadline_us": 2 ** 63 - 1})
    codec.encode({"v": 1, "t": "send", "deadline_us": -(2 ** 63)})


# ---- the two-body form -------------------------------------------------
#
# Plan 4's `exchange` frame carries a request AND a response, and they cannot
# share one opaque body: the far side content-addresses each on its own. The
# form declares itself in the header under `codec.BODIES_KEY` and packs the
# body slot as [len(first)][first][len(second)][second], leaving the OUTER
# frame -- length prefix, header, newline, body slot -- exactly as it was.


# The SAME literal CodecTest.java records for the same inputs. Two codecs that
# only round-trip against themselves can disagree forever, which is why the
# golden vectors exist at all; this is that pin for the two-body form. It is a
# literal here rather than a row in frames.json because every consumer of that
# file calls the ONE-body encoder.
TWO_BODY_HEX = (
    "0000004f7b2276223a312c2274223a2265786368616e6765222c2275726c223a"
    "22687474703a2f2f6170702e746573742f78222c22626f64696573223a327d0a"
    "0000000352455100000008524553504f4e5345"
)


def _exchange_header():
    return {"v": 1, "t": "exchange", "url": "http://app.test/x"}


def test_the_two_body_wire_form_is_the_same_on_both_sides():
    raw = codec.encode_two(_exchange_header(), b"REQ", b"RESPONSE")
    assert raw.hex() == TWO_BODY_HEX
    header, body, _ = codec.decode(bytes.fromhex(TWO_BODY_HEX))
    assert codec.split_bodies(header, body) == (b"REQ", b"RESPONSE")


def test_two_bodies_round_trip_and_stay_apart():
    """A first half whose own bytes look like a length prefix, and an empty
    second half: the pair that separates real length prefixes from a scan."""
    first, second = b"\x00\x00\x00\x08x", b""
    header, body, _ = codec.decode(codec.encode_two(_exchange_header(), first, second))
    assert codec.split_bodies(header, body) == (first, second)

    big = bytes(range(256)) * 300
    header, body, _ = codec.decode(codec.encode_two(_exchange_header(), big, big))
    assert codec.split_bodies(header, body) == (big, big)


def test_the_one_body_form_is_untouched_by_the_two_body_form():
    """Every existing frame goes through `encode`, and the golden vectors pin
    their bytes. This says it from the other side: a one-body frame declares
    no `bodies`, so nothing can read its payload as two halves."""
    header, body, _ = codec.decode(codec.encode(_exchange_header(), b"BODY"))
    assert codec.BODIES_KEY not in header
    assert body == b"BODY"
    with pytest.raises(codec.FrameError, match="one body, not two"):
        codec.split_bodies(header, body)


def test_encode_two_has_no_caller_outside_the_tests():
    """The bound the split-point asymmetry rests on, made falsifiable.

    `codec.decode` deliberately does NOT split the two bodies and Java's
    `Frame.decode` does; the note at `split_bodies` says the asymmetry "is
    bounded: two-body frames travel Burp -> Python only". Nothing enforced
    that. Java pins its half -- `Frame.encode(` has exactly two call sites in
    `extension/src`, both in BridgeClient, and the golden vectors redden if a
    third appears -- and this is the matching pin: the only encoder of a
    two-body frame on this side has no production caller, so this side emits
    none.

    A search over `src/`, not an import graph: a call reached through
    `getattr` or a re-export would slip past the latter, and the string is
    what a reviewer greps for anyway.
    """
    src = Path(__file__).resolve().parents[1] / "src"
    callers = sorted(
        f"{p.relative_to(src).as_posix()}:{n}"
        for p in src.rglob("*.py")
        for n, line in enumerate(p.read_text().splitlines(), 1)
        if "encode_two(" in line and not line.lstrip().startswith("def ")
    )
    assert callers == [], (
        "encode_two now has production callers "
        f"({callers}); two-body frames travel Burp -> Python only, and the "
        "note at codec.split_bodies rests on that. Python -> Burp two-body "
        "traffic means Java's eager split CLOSES the connection where this "
        "side counts and continues -- DENY-ALL, and the halt path with it."
    )


def test_two_bodies_over_max_frame_are_refused_before_they_are_joined():
    """Mirrors `Frame.encode(header, a, b)`, which checks first for the same
    reason: a bound on how much one frame may make the process allocate is
    lost if it is enforced after the allocation."""
    half = b"x" * (codec.MAX_FRAME // 2 + 16)
    with pytest.raises(codec.FrameError, match="exceed MAX_FRAME"):
        codec.encode_two(_exchange_header(), half, half)


def test_encoding_two_bodies_does_not_stamp_the_callers_header():
    """Or the next frame that header builds silently declares two bodies it
    has not got."""
    header = _exchange_header()
    codec.encode_two(header, b"a", b"b")
    assert codec.BODIES_KEY not in header


@pytest.mark.parametrize("payload,why", [
    (b"\x00\x00", "no length prefix for its first body"),
    (b"\x00\x00\x00\x63a", "declares a first body of 99"),
    (b"\x00\x00\x00\x01a\x00\x00\x00\x63", "declares bodies of 1 \\+ 99"),
    (b"\x00\x00\x00\x01a\x00\x00\x00\x01bX", "do not fill"),
])
def test_a_malformed_two_body_payload_is_refused(payload, why):
    """Each is a payload a lenient reader would accept by guessing, and each
    guess is a different pair of halves than the writer meant. EXACT FIT is
    required: the lengths are on the wire so neither side has to guess."""
    raw = codec.encode({**_exchange_header(), codec.BODIES_KEY: 2}, payload)
    header, body, _ = codec.decode(raw)
    with pytest.raises(codec.FrameError, match=why):
        codec.split_bodies(header, body)


@pytest.mark.parametrize("declared", [1, 3, 0, True])
def test_a_bodies_count_this_version_does_not_know_is_refused(declared):
    """`bodies` is a declaration, not a hint. `True` is in this list because
    `True == 1` in Python and a header may legitimately carry bools, so an
    `== 2` test written the obvious way on a future version that accepted 1
    would let it through."""
    raw = codec.encode({**_exchange_header(), codec.BODIES_KEY: declared}, b"abc")
    header, body, _ = codec.decode(raw)
    with pytest.raises(codec.FrameError, match="reads 2 and no other value"):
        codec.split_bodies(header, body)


def test_the_java_side_rejects_the_same_malformed_two_body_payloads():
    """The same payloads are refused on both sides, at different POINTS.

    Java's `Frame.decode` splits eagerly and raises there. This side splits at
    `split_bodies`, so a mis-packed capture frame is counted by BridgeServer
    rather than closing the control channel -- see the note in `decode`. What
    is shared is the four payloads, the unknown-count case, and the bytes
    below; what differs is which call raises.

    The Java half is CodecTest.malformedTwoBodyPayloadsAreRefused. Named here
    so a change to one is a change someone can find in the other; there is no
    JVM in this suite to run it from.
    """
    java = Path(__file__).parents[1] / "extension" / "test" / "hx" / "bridge" / "CodecTest.java"
    text = java.read_text()
    assert "malformedTwoBodyPayloadsAreRefused" in text
    # The literal itself, reassembled from the Java string concatenation, so a
    # drift in either file's expected bytes reddens here rather than waiting
    # for someone to run the other suite.
    declaration = text.split("TWO_BODY_HEX =", 1)[1].split(";", 1)[0]
    assert "".join(re.findall(r'"([0-9a-f]*)"', declaration)) == TWO_BODY_HEX


def test_a_blank_origin_is_refused_on_both_sides():
    """Finding 2 of the Task 3 review: the asymmetry in re-validation.

    `identity_id` and `value` both refuse emptiness; `origins` refused only a
    MISSING list, so `[""]` passed. An origin that matches no host is not a
    narrower bound, it is a dead rule -- and the caller believes it registered
    a restriction the extension will never apply, which is the wrong direction
    for a value whose whole job is to stop a credential going to the wrong
    host.
    """
    with pytest.raises(codec.FrameError, match="origin"):
        codec.identity_body("user", 1, "Cookie", "v", ("",))
    good = codec.identity_body("user", 1, "Cookie", "v", ("https://app.test",))
    tampered = good.replace(b'"https://app.test"', b'"   "')
    with pytest.raises(codec.FrameError, match="origin"):
        codec.parse_identity(tampered)
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


def identity_body(identity_id: str, generation: int, header: str, value: str,
                  origins: tuple[str, ...]) -> bytes:
    """The `identity` frame's body: `{identity_id, generation,
    inject: {header, value}, origins}`, JSON-encoded.

    NOT A CONFIG KEY, and the reason is spec section 5's: a `configure` naming
    a different rate or budget is REFUSED rather than applied, because a run
    must not talk its way into a larger allowance mid-flight. A programmatic
    refresh has to advance a generation WITHOUT re-opening scope, so folding
    identity into `configure` would either weaken that rule or make refresh
    impossible. Its own frame keeps both intact -- see `BridgeServer.
    register_identity`, which sends this body under `t: "identity"` rather
    than through `configure`.

    GENERATION MUST BE >= 1, validated here rather than left for the
    extension-side registry alone to catch: the registry treats a lower
    generation than the one it holds as a refusal, so 0 or negative could
    never be above anything it holds, and is a malformed frame here rather
    than a refusal there.
    """
    if not identity_id:
        raise FrameError("an identity frame needs an identity_id")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        raise FrameError(f"generation must be an integer >= 1, got {generation!r}")
    if not header:
        raise FrameError("an identity frame needs a header to inject into")
    if not value:
        raise FrameError("an identity frame with no value registers nothing")
    if not origins or not all(o and o.strip() for o in origins):
        raise FrameError(
            "an identity frame needs at least one origin; an identity with no "
            "origin could be applied to any host the scope allows")
    payload = {
        "identity_id": identity_id,
        "generation": generation,
        "inject": {"header": header, "value": value},
        "origins": list(origins),
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def parse_identity(body: bytes) -> dict:
    """The reverse of `identity_body`.

    Re-validates the same fields rather than trusting the writer, on the
    principle `parse_config_body` already follows: a body is checked on the
    reading side because the writing side being in this repo is not a
    guarantee about what actually arrived on the wire.
    """
    try:
        payload = json.loads(body.decode("utf-8"))
    except ValueError as exc:  # UnicodeDecodeError is a ValueError
        raise FrameError(f"identity body is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise FrameError("identity body must be a JSON object")

    identity_id = payload.get("identity_id")
    if not identity_id or not isinstance(identity_id, str):
        raise FrameError("an identity frame needs an identity_id")

    generation = payload.get("generation")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        raise FrameError(f"generation must be an integer >= 1, got {generation!r}")

    inject = payload.get("inject")
    if not isinstance(inject, dict):
        raise FrameError("an identity frame needs an inject object")
    header = inject.get("header")
    if not header or not isinstance(header, str):
        raise FrameError("an identity frame needs a header to inject into")
    value = inject.get("value")
    if not value or not isinstance(value, str):
        raise FrameError("an identity frame with no value registers nothing")

    origins = payload.get("origins")
    # A BLANK origin is refused alongside a missing list, for the same reason
    # `identity_id` and `value` refuse emptiness: an entry that matches no host
    # is not a narrower scope, it is a silently dead rule -- and the caller
    # believes it registered a bound the extension will never apply.
    if not origins or not isinstance(origins, list) or not all(
            isinstance(o, str) and o.strip() for o in origins):
        raise FrameError(
            "an identity frame needs at least one origin; an identity with no "
            "origin could be applied to any host the scope allows")

    return {
        "identity_id": identity_id,
        "generation": generation,
        "inject": {"header": header, "value": value},
        "origins": origins,
    }


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

import hx.TestSupport;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.*;

/** Hand-rolled runner: JUnit would be a dependency, and this jar has none. */
public class CodecTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    /** Runs one test method under the shared per-method guard: a throw out of
     *  it becomes a named FAIL against THIS class's counter instead of ending
     *  main() with the methods after it unrun and no summary line printed.
     *  See {@link hx.TestSupport#t}. */
    static void t(String name, TestSupport.Body body) {
        TestSupport.t(CodecTest::check, name, body);
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
        t("headerRoundTrip", CodecTest::headerRoundTrip);
        t("bodyIsVerbatim", CodecTest::bodyIsVerbatim);
        t("bodyNewlinesDoNotConfuseTheHeaderSplit", CodecTest::bodyNewlinesDoNotConfuseTheHeaderSplit);
        t("incompleteIsDistinctFromCorrupt", CodecTest::incompleteIsDistinctFromCorrupt);
        t("oversizedLengthIsRefused", CodecTest::oversizedLengthIsRefused);
        t("readReassemblesAcrossChunks", CodecTest::readReassemblesAcrossChunks);
        t("readerKeepsCoalescedFrames", CodecTest::readerKeepsCoalescedFrames);
        t("readerSurvivesArbitraryChunkBoundaries", CodecTest::readerSurvivesArbitraryChunkBoundaries);
        t("readerDistinguishesCleanCloseFromTruncation", CodecTest::readerDistinguishesCleanCloseFromTruncation);
        t("readerRejectsAnOversizedPrefixBeforeAllocating", CodecTest::readerRejectsAnOversizedPrefixBeforeAllocating);
        t("configBody", CodecTest::configBody);
        t("configBodyResultIsFrozen", CodecTest::configBodyResultIsFrozen);
        t("goldenVectors", CodecTest::goldenVectors);
        t("malformedInputsAreRejected", CodecTest::malformedInputsAreRejected);
        t("invalidUtf8HeaderIsRejected", CodecTest::invalidUtf8HeaderIsRejected);
        t("pairedSurrogateEqualsRawSupplementaryCharacter", CodecTest::pairedSurrogateEqualsRawSupplementaryCharacter);
        t("twoBodiesRoundTripAndStayApart", CodecTest::twoBodiesRoundTripAndStayApart);
        t("theOneBodyFormIsUntouchedByTheTwoBodyForm",
          CodecTest::theOneBodyFormIsUntouchedByTheTwoBodyForm);
        t("malformedTwoBodyPayloadsAreRefused", CodecTest::malformedTwoBodyPayloadsAreRefused);
        t("theTwoBodyWireFormIsTheSameOnBothSides",
          CodecTest::theTwoBodyWireFormIsTheSameOnBothSides);

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
        Frame.Decoded d = new Frame.Reader(new ByteArrayInputStream(raw)).read();
        check("read() reassembles a large frame", Arrays.equals(d.body, payload));
    }

    static void readerKeepsCoalescedFrames() throws Exception {
        byte[] f1 = Frame.encode(Map.of("v", 1L, "t", "configure"), new byte[0]);
        byte[] f2 = Frame.encode(Map.of("v", 1L, "t", "halt"), "body".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream both = new ByteArrayOutputStream();
        both.write(f1); both.write(f2);

        Frame.Reader r = new Frame.Reader(new ByteArrayInputStream(both.toByteArray()));
        check("coalesced frame 1", "configure".equals(r.read().header.get("t")));
        Frame.Decoded second = r.read();
        // The whole point: a call-local buffer loses this one.
        check("coalesced frame 2 survives", "halt".equals(second.header.get("t")));
        check("coalesced frame 2 body intact",
              "body".equals(new String(second.body, StandardCharsets.UTF_8)));
    }

    static void readerSurvivesArbitraryChunkBoundaries() throws Exception {
        byte[] f1 = Frame.encode(Map.of("v", 1L, "t", "configure"), new byte[0]);
        byte[] f2 = Frame.encode(Map.of("v", 1L, "t", "halt"), "body".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream three = new ByteArrayOutputStream();
        three.write(f1); three.write(f2); three.write(f1);
        final byte[] all = three.toByteArray();

        InputStream sevenAtATime = new InputStream() {
            int i = 0;
            public int read() { return i < all.length ? (all[i++] & 0xff) : -1; }
            public int read(byte[] b, int off, int l) {
                if (i >= all.length) return -1;
                int n = Math.min(7, Math.min(l, all.length - i));
                System.arraycopy(all, i, b, off, n); i += n; return n;
            }
        };
        Frame.Reader r = new Frame.Reader(sevenAtATime);
        check("7-byte chunks: frame 1", "configure".equals(r.read().header.get("t")));
        check("7-byte chunks: frame 2", "halt".equals(r.read().header.get("t")));
        check("7-byte chunks: frame 3", "configure".equals(r.read().header.get("t")));
    }

    static void readerDistinguishesCleanCloseFromTruncation() throws Exception {
        byte[] f1 = Frame.encode(Map.of("v", 1L, "t", "configure"), new byte[0]);

        Frame.Reader clean = new Frame.Reader(new ByteArrayInputStream(f1));
        clean.read();
        boolean ok = false;
        try { clean.read(); } catch (Frame.PeerClosed e) { ok = "peer closed".equals(e.getMessage()); }
        check("clean close at a frame boundary is not an error condition", ok);

        byte[] truncated = Arrays.copyOfRange(f1, 0, f1.length - 3);
        ok = false;
        try { new Frame.Reader(new ByteArrayInputStream(truncated)).read(); }
        catch (Frame.PeerClosed e) { ok = "peer closed mid-frame".equals(e.getMessage()); }
        check("a truncated frame is reported as mid-frame", ok);
    }

    static void readerRejectsAnOversizedPrefixBeforeAllocating() throws Exception {
        byte[] huge = new byte[] {(byte) 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff, 'x'};
        boolean ok = false;
        try { new Frame.Reader(new ByteArrayInputStream(huge)).read(); }
        catch (Frame.FrameError e) { ok = e.getMessage().contains("exceeds MAX_FRAME"); }
        check("oversized length prefix rejected before allocation", ok);
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

    /** ConfigBody.parse() is the only producer of the map BridgeClient hands
     *  out via authorisation()/scopeConfig(). A holder that could widen it in
     *  place would be authorising itself for a scope no configure frame ever
     *  set -- no epoch bump, no log line. Both levels must be frozen: the
     *  outer map AND every inner list. */
    static void configBodyResultIsFrozen() {
        byte[] body = "scope.include\thttps://a/*\n".getBytes(StandardCharsets.UTF_8);
        // A fresh parse per assertion. Sharing one map lets the first
        // assertion corrupt the second: if the outer map is NOT frozen, the
        // put() succeeds and replaces the value with an immutable List.of(),
        // so the inner-list assertion then passes for entirely the wrong
        // reason and the failure output points at one level when both are
        // broken.
        Map<String, List<String>> outer = ConfigBody.parse(body);
        expectThrows("the map itself rejects mutation", UnsupportedOperationException.class,
                     () -> outer.put("scope.include", List.of("https://evil/*")));

        Map<String, List<String>> inner = ConfigBody.parse(body);
        expectThrows("an inner list rejects mutation", UnsupportedOperationException.class,
                     () -> inner.get("scope.include").add("https://evil/*"));
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

    /**
     * Well-formed vectors can only pin agreement on what is VALID. They say
     * nothing about whether both sides reject the same hostile input the same
     * way -- which is exactly how a NumberFormatException escaped Frame.decode
     * in the first place. This pins rejection too, on both Json.parse directly
     * and on Frame.decode once the same text is wrapped in a real frame.
     */
    static void malformedInputsAreRejected() throws Exception {
        Path p = Path.of("..", "tests", "vectors", "malformed.json");
        String text = Files.readString(p, StandardCharsets.UTF_8);
        List<Map<String, Object>> cases = MalformedVectorReader.cases(text);
        check("malformed vectors file has cases", !cases.isEmpty());
        for (Map<String, Object> c : cases) {
            String name = (String) c.get("name");
            String headerText = (String) c.get("header_text");

            expectThrows("malformed " + name + ": Json.parse rejects it",
                         Json.JsonError.class, () -> Json.parse(headerText));

            byte[] raw = rawFrame(headerText.getBytes(StandardCharsets.UTF_8));
            expectThrows("malformed " + name + ": Frame.decode rejects it wrapped in a frame",
                         Frame.FrameError.class, () -> Frame.decode(raw));
        }
    }

    /**
     * Java's default decoder REPLACES malformed bytes with U+FFFD instead of
     * raising, silently accepting a frame Python rejects outright. Frame.decode
     * therefore decodes the header STRICTLY, and this is the check that pins it.
     *
     * The bad byte has to sit INSIDE an otherwise well-formed header for the
     * check to be able to fail. This one guarded the strict decoder with
     * {0xC3, 0x28} alone, which is not JSON under EITHER decoding: Json.parse
     * threw regardless, so replacing the CharsetDecoder with a lenient
     * `new String(...)` still printed ok. Measured.
     *
     * Direction matters, which is why this is worth pinning at all. On
     * 000000147b2276223a312c2274223a2268656cff6f227d0a:
     *
     *   JAVA lenient : ACCEPTED   t = "hel\uFFFDo"
     *   JAVA strict  : REJECTED   header bytes are not valid UTF-8
     *   PYTHON       : REJECTED   'utf-8' codec can't decode byte 0xff
     *
     * Strict means FrameError, which trips readLoop()'s finally and denyAll().
     * Lenient means a mangled `t` falls through to
     * `default -> error(f, "unknown_frame"); return true` and the connection
     * CARRIES ON under the standing scope -- on a frame the harness would
     * never have accepted.
     */
    static void invalidUtf8HeaderIsRejected() {
        // {"v":1,"t":"hel<0xFF>o"} -- valid JSON with both required fields the
        // moment 0xFF is leniently replaced by U+FFFD, so a lenient decode is
        // ACCEPTED here rather than dying in the parser.
        byte[] inside = new byte[] {
            '{', '"', 'v', '"', ':', '1', ',', '"', 't', '"', ':', '"',
            'h', 'e', 'l', (byte) 0xFF, 'o', '"', '}'
        };
        byte[] rawInside = rawFrame(inside);
        expectThrows("invalid UTF-8 INSIDE an otherwise valid header raises FrameError, "
                     + "not a U+FFFD-mangled frame type",
                     Frame.FrameError.class, () -> Frame.decode(rawInside));

        // Kept as well: 0xC3 starts a 2-byte sequence that must be followed by
        // a continuation byte (0x80-0xBF), and 0x28 '(' is not one. This one
        // cannot distinguish strict from lenient on its own -- see above -- but
        // it costs nothing and pins the truncated-sequence shape too.
        byte[] bad = new byte[] { (byte) 0xC3, 0x28 };
        byte[] raw = rawFrame(bad);
        expectThrows("invalid UTF-8 header (0xC3 0x28) raises FrameError, not U+FFFD",
                     Frame.FrameError.class, () -> Frame.decode(raw));
    }

    /**
     * A supplementary character is legally encoded in JSON as a PAIR of \\u
     * escapes -- exactly what json.dumps emits by default (ensure_ascii=True)
     * -- and separately as a raw UTF-8 character, which is what our own
     * codec emits (ensure_ascii=False). Both must parse to the identical
     * Java string, or a peer that switches encoding style produces a frame
     * this side reads differently -- or not at all.
     */
    static void pairedSurrogateEqualsRawSupplementaryCharacter() {
        // Escaped form: a literal \\u83d\\ude00 pair IN THE JSON TEXT, for
        // Json.parse's own escape handling to combine at runtime. (Double
        // backslashes here so javac leaves the backslash in the string --
        // a single \\u escape would be consumed by the COMPILER instead.)
        Map<String, Object> escaped = Json.parse("{\"v\":1,\"t\":\"x\",\"a\":\"\\ud83d\\ude00\"}");
        // Unescaped form: javac's OWN \\u processing embeds the actual
        // surrogate pair directly into this Java string literal at compile
        // time -- equivalent to typing the raw emoji glyph in UTF-8 source.
        Map<String, Object> raw = Json.parse("{\"v\":1,\"t\":\"x\",\"a\":\"😀\"}");
        check("escaped surrogate pair equals the raw supplementary character",
              escaped.equals(raw) && "😀".equals(escaped.get("a")));
    }

    /** [4-byte BE length][headerBytes]\n -- built by hand so a header that is
     * not valid JSON (most of malformed.json isn't) can still be wrapped in a
     * real frame; Frame.encode itself would refuse to write such a header. */
    static byte[] rawFrame(byte[] headerBytes) {
        byte[] payload = new byte[headerBytes.length + 1];
        System.arraycopy(headerBytes, 0, payload, 0, headerBytes.length);
        payload[headerBytes.length] = '\n';
        int len = payload.length;
        byte[] raw = new byte[4 + len];
        raw[0] = (byte) (len >>> 24); raw[1] = (byte) (len >>> 16);
        raw[2] = (byte) (len >>> 8);  raw[3] = (byte) len;
        System.arraycopy(payload, 0, raw, 4, len);
        return raw;
    }

    // ---- the two-body form ---------------------------------------------

    /**
     * The SAME bytes tests/test_bridge_codec.py records for the same inputs.
     *
     * A frame both codecs merely round-trip against THEMSELVES is a frame two
     * implementations can disagree about forever: the existing golden vectors
     * exist for exactly that reason, and the two-body form needs its own,
     * because none of them declares `bodies`. Written as a literal in both
     * files rather than added to frames.json, whose every consumer calls the
     * ONE-body encoder.
     */
    static final String TWO_BODY_HEX =
        "0000004f7b2276223a312c2274223a2265786368616e6765222c2275726c223a"
      + "22687474703a2f2f6170702e746573742f78222c22626f64696573223a327d0a"
      + "0000000352455100000008524553504f4e5345";

    static Map<String, Object> exchangeHeader() {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("v", 1L);
        h.put("t", "exchange");
        h.put("url", "http://app.test/x");
        return h;
    }

    static void theTwoBodyWireFormIsTheSameOnBothSides() {
        byte[] raw = Frame.encode(exchangeHeader(),
                                  "REQ".getBytes(StandardCharsets.UTF_8),
                                  "RESPONSE".getBytes(StandardCharsets.UTF_8));
        check("the two-body frame is byte-for-byte what Python writes ("
              + hex(raw) + ")", TWO_BODY_HEX.equals(hex(raw)));
        Frame.Decoded d = Frame.decode(unhex(TWO_BODY_HEX));
        check("and Python's bytes decode here to the same request half",
              "REQ".equals(new String(d.body, StandardCharsets.UTF_8)));
        check("and to the same response half",
              d.second != null
              && "RESPONSE".equals(new String(d.second, StandardCharsets.UTF_8)));
    }

    static void twoBodiesRoundTripAndStayApart() {
        // Two EMPTY halves, and a first half whose bytes are a plausible
        // length prefix of their own: the case that separates real length
        // prefixes from a delimiter scan.
        byte[] first = new byte[] {0, 0, 0, 8, 'x'};
        byte[] second = new byte[0];
        Frame.Decoded d = Frame.decode(Frame.encode(exchangeHeader(), first, second));
        check("a first half that looks like a length prefix survives whole",
              Arrays.equals(first, d.body));
        check("an EMPTY second half is an empty array, not a null -- an "
              + "exchange with no response is not a one-body frame",
              d.second != null && d.second.length == 0);

        byte[] big = new byte[70000];
        for (int i = 0; i < big.length; i++) big[i] = (byte) i;
        Frame.Decoded e = Frame.decode(Frame.encode(exchangeHeader(), big, big));
        check("a body larger than one read chunk round-trips as the first half",
              Arrays.equals(big, e.body));
        check("and as the second", Arrays.equals(big, e.second));
    }

    static void theOneBodyFormIsUntouchedByTheTwoBodyForm() {
        // Item 5 of this task: every existing frame goes through Frame, and
        // the golden vectors pin their bytes. This says the same thing from
        // the other side -- a one-body frame decodes with NO second body, so
        // nothing that reads `second` can mistake a payload for two halves.
        Map<String, Object> h = exchangeHeader();
        byte[] raw = Frame.encode(h, "BODY".getBytes(StandardCharsets.UTF_8));
        Frame.Decoded d = Frame.decode(raw);
        check("a one-body frame has no second body", d.second == null);
        check("and its body is the whole payload",
              "BODY".equals(new String(d.body, StandardCharsets.UTF_8)));
        check("and its header carries no " + Frame.BODIES_KEY + " key",
              !d.header.containsKey(Frame.BODIES_KEY));
        // The stamp goes on a COPY: a caller's map must not come back mutated,
        // or the next frame it builds silently declares two bodies it has not
        // got.
        Frame.encode(h, "a".getBytes(StandardCharsets.UTF_8),
                     "b".getBytes(StandardCharsets.UTF_8));
        check("and encoding two bodies did not stamp the caller's header",
              !h.containsKey(Frame.BODIES_KEY));
    }

    static void malformedTwoBodyPayloadsAreRefused() {
        // Each case is a payload a lenient reader would accept by guessing,
        // and each guess is a different pair of halves than the writer meant.
        expectThrows("a payload too short to hold a first length prefix",
                     Frame.FrameError.class,
                     () -> Frame.decode(twoBodyFrame(new byte[] {0, 0})));
        expectThrows("a first length that runs past the payload",
                     Frame.FrameError.class,
                     () -> Frame.decode(twoBodyFrame(new byte[] {0, 0, 0, 99, 'a'})));
        expectThrows("a second length that runs past the payload",
                     Frame.FrameError.class,
                     () -> Frame.decode(twoBodyFrame(
                         new byte[] {0, 0, 0, 1, 'a', 0, 0, 0, 99})));
        expectThrows("bodies that leave trailing bytes behind them",
                     Frame.FrameError.class,
                     () -> Frame.decode(twoBodyFrame(
                         new byte[] {0, 0, 0, 1, 'a', 0, 0, 0, 1, 'b', 'X'})));
        // `bodies` is a declaration, not a hint: a value this version does not
        // know is a frame it cannot read, and reading it as one body would
        // hand the far side a request with a response spliced onto it.
        Map<String, Object> three = exchangeHeader();
        three.put(Frame.BODIES_KEY, 3L);
        expectThrows("a bodies count this version does not know",
                     Frame.FrameError.class,
                     () -> Frame.decode(Frame.encode(three, new byte[] {1, 2, 3})));
    }

    /** A frame declaring two bodies over a payload chosen by the caller. */
    static byte[] twoBodyFrame(byte[] payload) {
        Map<String, Object> h = exchangeHeader();
        h.put(Frame.BODIES_KEY, 2L);
        return Frame.encode(h, payload);
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
 * design, and each vector entry nests a "header" object one level deep, so
 * this reader carves the header substring out and parses it on its own (it
 * IS flat by itself), then parses the rest of the entry -- with a string
 * placeholder standing in for the header -- through the same flat parser.
 * Widening Json.parse to accept nesting, just to satisfy a test, is the
 * wrong trade.
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
                if (depth == 0) out.add(parseEntry(text.substring(objStart, p + 1)));
            } else if (c == ']' && depth == 0) break;
        }
        return out;
    }

    /**
     * A frame entry is flat except for its one nested "header" object. Carve
     * the header out, parse it on its own, and parse the remainder -- with a
     * string placeholder standing in for header -- with the same flat parser.
     */
    private static Map<String, Object> parseEntry(String entry) {
        int hk = entry.indexOf("\"header\"");
        if (hk < 0) throw new IllegalArgumentException("frame entry has no header: " + entry);
        int hStart = entry.indexOf('{', hk);
        int hEnd = matchBrace(entry, hStart);
        Map<String, Object> header = Json.parse(entry.substring(hStart, hEnd + 1));

        String flattened = entry.substring(0, hStart) + "\"\"" + entry.substring(hEnd + 1);
        Map<String, Object> out = new LinkedHashMap<>(Json.parse(flattened));
        out.put("header", header);
        return out;
    }

    private static int matchBrace(String s, int open) {
        int depth = 0;
        for (int p = open; p < s.length(); p++) {
            char c = s.charAt(p);
            if (c == '"') { p = skipString(s, p); continue; }
            if (c == '{') depth++;
            else if (c == '}') { depth--; if (depth == 0) return p; }
        }
        throw new IllegalArgumentException("unterminated object");
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
And its sibling, which the same `CodecTest` needs and which no step ever
introduced -- the repo has carried it since Task 2:

```java
// extension/test/hx/bridge/MalformedVectorReader.java
package hx.bridge;

import java.util.*;

/**
 * Reads tests/vectors/malformed.json. Unlike frames.json, every case object
 * here is flat -- name, header_text and why are all plain strings -- so the
 * ordinary flat Json.parse can read each case directly; only the outer
 * "cases" array needs a hand-rolled boundary scan.
 */
final class MalformedVectorReader {

    static List<Map<String, Object>> cases(String text) {
        List<Map<String, Object>> out = new ArrayList<>();
        int i = text.indexOf("\"cases\"");
        if (i < 0) throw new IllegalArgumentException("no cases key");
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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A JSON reader and writer. The HEADER it writes and reads is FLAT; a frame
 * BODY it reads may nest.
 *
 * {@link #write} and {@link #parse} are the header pair, and header values may
 * be string, integer, boolean or null -- no nested objects, no arrays. That is
 * not a shortcut, it is the contract: the bridge header schema is flat
 * precisely so this parser stays small enough to be obviously correct, and
 * structured payloads travel in the frame body instead. A nested value in a
 * header is rejected loudly rather than half-parsed.
 *
 * {@link #parseBody} is the BODY reader, and it is the same grammar with
 * nesting allowed and a depth bound. It exists because the `identity` frame's
 * body IS a structured payload -- `{"inject": {"header": ..., "value": ...},
 * "origins": [...]}` -- written by `hx.bridge.codec.identity_body` on the
 * Python side. ONE grammar and not two: the alternative was a second JSON
 * reader for that one body, and two readers of one grammar that disagree
 * about a surrogate pair, a control character or a leading zero is a frame
 * that is valid on one side of the bridge and not the other. Nothing is
 * loosened for the header path -- {@link #parse} sets the flag that permits
 * nesting to false and every existing refusal is byte-identical.
 */
public final class Json {

    public static class JsonError extends RuntimeException {
        public JsonError(String m) { super(m); }
    }

    /**
     * How many objects and arrays a body may nest INSIDE its outermost object.
     *
     * A BOUND, because the alternative to one is a StackOverflowError. A frame
     * body is bounded only by {@link Frame#MAX_FRAME} -- 64 MB -- so a body of
     * `[[[[[...` recurses as far as the peer chose to write, and a
     * StackOverflowError is an Error rather than a RuntimeException: it is not
     * a {@link JsonError} that any arm of the frame switch answers with a
     * refusal. The identity body needs ONE level of nesting (`inject`, and
     * `origins` beside it), so eight is generous for every body this protocol
     * has and small enough that nothing can be reached through it.
     */
    static final int MAX_DEPTH = 8;

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

    /** A frame HEADER: a FLAT object, exactly as before. */
    public static Map<String, Object> parse(String text) {
        return parse(text, false, "header");
    }

    /**
     * A frame BODY: the same grammar with nesting allowed, bounded by
     * {@link #MAX_DEPTH}.
     *
     * A separate entry point rather than a flag on {@link #parse}, so that no
     * caller reaches nesting by accident and every header stays as flat as it
     * was. The one body that uses it today is the `identity` frame's; see
     * {@link IdentityBody}, which owns the SCHEMA while this owns the grammar.
     */
    public static Map<String, Object> parseBody(String text) {
        return parse(text, true, "body");
    }

    private static Map<String, Object> parse(String text, boolean nested, String what) {
        P p = new P(text, nested);
        Map<String, Object> out = parseObject(p);
        p.ws();
        // Python's json.loads raises "Extra data" here. Accepting it would let a
        // crafted frame be valid on one side of the bridge and not the other.
        if (p.i != text.length())
            throw new JsonError("trailing data after the " + what + " object at " + p.i);
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

    /** A JSON array, for a body. Header values never reach this. */
    private static List<Object> parseArray(P p) {
        p.ws();
        p.expect('[');
        List<Object> out = new ArrayList<>();
        p.ws();
        if (p.peek() == ']') { p.next(); return out; }
        while (true) {
            p.ws();
            out.add(p.value());
            p.ws();
            char c = p.next();
            if (c == ']') return out;
            if (c != ',') throw new JsonError("expected ',' or ']' at " + p.i);
        }
    }

    private static final class P {
        final String s;
        /** Whether a nested object or array is a value here. False for every
         *  header, which is what keeps the header schema flat. */
        final boolean nested;
        /** How many objects and arrays are open above the value being read. */
        int depth = 0;
        int i = 0;
        P(String s, boolean nested) { this.s = s; this.nested = nested; }

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
                        // \\u escapes, and json.dumps emits exactly that by default
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
            if (c == '{' || c == '[') {
                if (!nested)
                    throw new JsonError("header must be flat; nested values are not supported");
                if (depth + 1 > MAX_DEPTH)
                    throw new JsonError("body nests deeper than " + MAX_DEPTH + " at " + i);
                depth++;
                Object v = c == '{' ? parseObject(this) : parseArray(this);
                depth--;
                return v;
            }
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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

/**
 * [4-byte BE length][header JSON]\n[body bytes]
 *
 * TWO BODIES, when a frame carries a request AND a response. Plan 4's
 * `exchange` frame has two halves and they cannot share one opaque body: the
 * far side content-addresses each independently. The two-body form declares
 * itself in the HEADER, under {@link #BODIES_KEY}, and packs the body slot as
 *
 *     [4-byte BE len(first)][first][4-byte BE len(second)][second]
 *
 * so the OUTER frame is unchanged: same length prefix, same header, same
 * newline, same opaque body slot. Every frame this jar wrote before -- hello,
 * configured, result, error, halted -- still goes through the one-body
 * {@link #encode(Map, byte[])} and is byte-identical to what it was.
 *
 * HOW TO FALSIFY THAT rather than take it on trust: `Frame.encode(` appears
 * exactly twice in extension/src, both inside BridgeClient's two `send`
 * overloads, and the three-argument one is reached only from
 * `BridgeClient.exchangeSink()`. A third call site, or a `send` that started
 * routing control frames through the two-body form, would make the sentence
 * false -- and would also redden CodecTest.goldenVectors and Python's
 * test_vectors_match_their_recorded_hex, which assert the same recorded bytes
 * from opposite sides of the bridge.
 */
public final class Frame {

    public static final int MAX_FRAME = 64 * 1024 * 1024;

    /**
     * The header key that says the body slot holds two length-prefixed bodies.
     *
     * In the HEADER rather than inferred from `t`, deliberately: the codec has
     * no business knowing the frame vocabulary, and a reader that guessed from
     * `t == "exchange"` would silently mis-parse the first frame type someone
     * adds with two bodies and forgets to teach it about. `codec.BODIES_KEY`
     * is the same string on the Python side.
     */
    public static final String BODIES_KEY = "bodies";

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
        /** The SECOND body, or null when the frame carries one. Null and
         *  zero-length are different answers: a two-body frame whose response
         *  half is empty decodes to an empty array here, and reading that as
         *  "there was no second half" is how an exchange with no response
         *  would come to look like an ordinary one-body frame. */
        public final byte[] second;
        public final int consumed;
        Decoded(Map<String, Object> header, byte[] body, int consumed) {
            this(header, body, null, consumed);
        }
        Decoded(Map<String, Object> header, byte[] body, byte[] second, int consumed) {
            this.header = header; this.body = body;
            this.second = second; this.consumed = consumed;
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

    /**
     * The two-body form: one frame carrying a request and a response.
     *
     * The header is COPIED and stamped with {@link #BODIES_KEY} here rather
     * than trusted from the caller, so the declaration on the wire and the
     * shape of the bytes cannot disagree -- a caller that forgot the key would
     * otherwise produce a frame whose second body is silently read as trailing
     * bytes of the first. The frame is then built by the one-body encoder
     * above, which is what keeps the outer form identical.
     */
    public static byte[] encode(Map<String, Object> header, byte[] first, byte[] second) {
        long total = 4L + first.length + 4L + second.length;
        // Checked before the arrays are joined, not after: MAX_FRAME exists so
        // one frame cannot make this JVM allocate arbitrarily, and a check that
        // runs after the allocation it is bounding has already lost.
        if (total > MAX_FRAME)
            throw new FrameError("two bodies of " + first.length + " + "
                                 + second.length + " exceed MAX_FRAME " + MAX_FRAME);
        byte[] payload = new byte[(int) total];
        putInt(payload, 0, first.length);
        System.arraycopy(first, 0, payload, 4, first.length);
        putInt(payload, 4 + first.length, second.length);
        System.arraycopy(second, 0, payload, 8 + first.length, second.length);
        Map<String, Object> stamped = new java.util.LinkedHashMap<>(header);
        stamped.put(BODIES_KEY, 2L);
        return encode(stamped, payload);
    }

    private static void putInt(byte[] out, int at, int v) {
        out[at] = (byte) (v >>> 24); out[at + 1] = (byte) (v >>> 16);
        out[at + 2] = (byte) (v >>> 8); out[at + 3] = (byte) v;
    }

    private static long getInt(byte[] b, int at) {
        return ((long) (b[at] & 0xff) << 24) | ((b[at + 1] & 0xff) << 16)
             | ((b[at + 2] & 0xff) << 8) | (b[at + 3] & 0xff);
    }

    /** Whether the header declares the two-body form. `2L` and nothing else:
     *  Json.parse yields Long for every integer, and a `bodies` this version
     *  does not know is a frame it cannot read, not one to guess at. */
    private static boolean declaresTwoBodies(Map<String, Object> header) {
        Object b = header.get(BODIES_KEY);
        if (b == null) return false;
        if (Long.valueOf(2L).equals(b)) return true;
        throw new FrameError("header declares " + BODIES_KEY + "=" + b
                             + "; this version reads 2 and no other value");
    }

    /**
     * Split a declared two-body payload. EXACT FIT is required: the two
     * declared lengths must consume the payload to its last byte. A payload
     * with bytes left over is a frame this side and the other side would read
     * differently, and the whole reason the lengths are on the wire at all is
     * so neither has to guess where the halves end.
     */
    private static byte[][] splitBodies(byte[] payload) {
        if (payload.length < 4)
            throw new FrameError("two-body frame has no length prefix for its first body");
        long n1 = getInt(payload, 0);
        if (payload.length < 4 + n1 + 4)
            throw new FrameError("two-body frame declares a first body of " + n1
                                 + " but holds " + payload.length + " bytes");
        long n2 = getInt(payload, (int) (4 + n1));
        if (payload.length != 8 + n1 + n2)
            throw new FrameError("two-body frame declares bodies of " + n1 + " + "
                                 + n2 + ", which do not fill its " + payload.length
                                 + " bytes");
        return new byte[][] {
            Arrays.copyOfRange(payload, 4, (int) (4 + n1)),
            Arrays.copyOfRange(payload, (int) (8 + n1), (int) (8 + n1 + n2)),
        };
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
        byte[] payload = Arrays.copyOfRange(buf, nl + 1, end);
        if (declaresTwoBodies(header)) {
            byte[][] two = splitBodies(payload);
            return new Decoded(header, two[0], two[1], end);
        }
        return new Decoded(header, payload, end);
    }

    /** Peer closed the connection. Distinct from Incomplete, which means
     *  "call again with more bytes". */
    public static class PeerClosed extends RuntimeException {
        public PeerClosed(String m) { super(m); }
    }

    /**
     * Reads frames from a stream, owning the buffer across calls.
     *
     * A bare read(InputStream) cannot be correct in a loop. decode() reports
     * `consumed` precisely because one read may deliver more than one frame,
     * and a method that returns after the first frame has nowhere to put the
     * remainder -- so it drops it, and the loss surfaces later as a misleading
     * "peer closed mid-frame". Owning the buffer is that somewhere. This
     * mirrors codec.FrameReader on the Python side, including reading the
     * length prefix first so draining a large frame is linear rather than
     * re-parsing a growing buffer once per chunk.
     *
     * A Reader belongs to exactly one thread. It is not merely unsynchronised:
     * `buf` and the hoisted `chunk` are per-Reader staging, so two concurrent
     * read() calls scribble over each other's bytes.
     */
    public static final class Reader {
        private final InputStream in;
        private byte[] buf = new byte[0];
        private int len = 0;                       // bytes of buf actually in use

        public Reader(InputStream in) { this.in = in; }

        private final byte[] chunk = new byte[65536];   // one per Reader, not per call

        public Decoded read() throws IOException {
            while (true) {
                if (len >= 4) {
                    long length = ((long) (buf[0] & 0xff) << 24) | ((buf[1] & 0xff) << 16)
                                | ((buf[2] & 0xff) << 8) | (buf[3] & 0xff);
                    // Checked before allocation: the prefix is attacker-influenced.
                    if (length > MAX_FRAME)
                        throw new FrameError("declared frame of " + length
                                             + " exceeds MAX_FRAME " + MAX_FRAME);
                    int end = (int) (4 + length);
                    if (len >= end) {
                        Decoded d = decode(Arrays.copyOfRange(buf, 0, end));
                        System.arraycopy(buf, d.consumed, buf, 0, len - d.consumed);
                        len -= d.consumed;
                        // One 64 MB frame must not pin 64 MB for the life of
                        // the connection -- but shrinking to 64 KB after every
                        // ordinary frame is worse than the leak it prevents:
                        // Plan 3's `exchange` frames carry HTTP bodies, and 200
                        // x 2 MB measured 206 ms of drop-and-re-double against
                        // 122 ms with this hysteresis. Trigger well above the
                        // working set, and never shrink below 1 MB.
                        if (buf.length > (1 << 22) && len < (buf.length >>> 2))
                            buf = Arrays.copyOf(buf, Math.max(len, 1 << 20));
                        return d;
                    }
                }
                int n = in.read(chunk);
                if (n < 0) throw new PeerClosed(len > 0 ? "peer closed mid-frame" : "peer closed");
                if (len + n > buf.length)
                    buf = Arrays.copyOf(buf, Math.max(len + n, Math.max(1024, buf.length * 2)));
                System.arraycopy(chunk, 0, buf, len, n);
                len += n;
            }
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

    /**
     * The keys that are read as numbers, and are therefore checked HERE.
     *
     * REPRODUCED END TO END over a unix socket before this existed:
     * `limit.rate_rps = as fast as possible` parsed fine, the extension acked
     * `t=configured epoch=1`, and the operator's console said the run was
     * configured. The FIRST send then threw out of Limits.arm, the send arm
     * answered `not_configured`, dropped to DENY-ALL and CLOSED -- and
     * HxExtension has no reconnect (`c.connect()` runs once, on a daemon
     * thread), so the corrected configure could not be sent at all:
     * `java.io.IOException: Broken pipe`. Recovery needed an extension reload
     * inside Burp.
     *
     * Refusing it here answers `bad_config` instead: the same DENY-ALL, the
     * same nothing-issued, but the channel lives and the next configure is
     * heard. Safety is identical; recoverability is not. An equally malformed
     * value arriving one frame later already got the survivable answer, and
     * that asymmetry was the whole argument.
     *
     * `limit.concurrency` is deliberately NOT in this list. Nothing reads it
     * yet -- refusing a config for a value no code consults would be this
     * parser inventing a rule rather than enforcing one. It joins the list in
     * the change that honours it.
     */
    private static final Set<String> POSITIVE_INTEGER_KEYS =
        Set.of("limit.rate_rps", "limit.max_requests");

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
        // parse() is the ONLY producer of a Map<String, List<String>> that
        // BridgeClient hands out (authorisation().scope() / scopeConfig()),
        // and nothing downstream mutates it after this call returns. Freeze
        // it here so that invariant holds by construction rather than by
        // convention: a holder that widened scope in place would authorise
        // requests under a scope no configure frame ever set, no epoch bump
        // and no log line to show for it.
        //
        // Both levels are needed: Map.copyOf alone would leave each inner
        // ArrayList mutable, and mutating a scope list in place authorises a
        // scope no configure frame ever set -- no epoch bump, no log line.
        //
        // The outer wrapper is unmodifiableMap over a LinkedHashMap rather
        // than Map.copyOf so that ITERATION order survives. Be clear about
        // what does and does not depend on that: CodecTest's "repeated keys
        // accumulate in order" asserts on the inner List, which List.copyOf
        // preserves either way -- swapping in Map.copyOf keeps the whole suite
        // green. Nothing tests map iteration order. It is preserved here
        // because a config's key order is the operator's, and an unordered
        // rendering of someone's scope in a report is a defect no test will
        // catch for you.
        // Checked after the whole body is read, so a repeated key is seen as
        // repeated. See POSITIVE_INTEGER_KEYS for why this is worth a frame
        // the caller can recover from.
        for (String key : POSITIVE_INTEGER_KEYS) positiveInteger(out.get(key), key);

        Map<String, List<String>> frozen = new LinkedHashMap<>();
        out.forEach((k, v) -> frozen.put(k, List.copyOf(v)));
        return Collections.unmodifiableMap(frozen);
    }

    /**
     * "integer, once" -- the protocol document's words for these keys -- read
     * as a refusal rather than as documentation.
     *
     * An absent key is fine: it means the operator expressed no opinion and
     * the jar's built-in default answers. A key that is PRESENT and unreadable
     * is not, and falling back to the default there is the one answer wrong in
     * both directions -- an operator who asked for 1 rps would silently get 5,
     * and one who asked for 500 would silently get 5 as well.
     *
     * Limits.positive still makes the same three checks on the value it
     * actually uses. That is not duplication to be tidied away: this one
     * guards the WIRE, and an Authorisation can be constructed without ever
     * crossing it.
     */
    private static void positiveInteger(List<String> values, String key) {
        if (values == null || values.isEmpty()) return;
        if (values.size() != 1)
            throw new Frame.FrameError(key + " was set " + values.size()
                + " times; it is an integer, once -- two answers to \"how fast\" "
                + "is not a limit");
        String raw = values.get(0).strip();
        long n;
        try {
            n = Long.parseLong(raw);
        } catch (NumberFormatException e) {
            throw new Frame.FrameError(key + " is not an integer: " + raw);
        }
        if (n <= 0) throw new Frame.FrameError(key + " must be positive, not " + n);
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
import logging
import os
import socket
import stat
import struct
import threading
import time
from pathlib import Path

import pytest

from hx import halt as halt_mod
from hx import identity
from hx.bridge import codec, server
from hx.store import db as db_mod
from hx.store import records
from hx.store.paths import secure_mkdir


@pytest.fixture
def store(tmp_path):
    """A real engagement database. Every BridgeServer in this file drives one:
    `operator_halt` is required, and a stub would hide the guarantee these
    tests exist for -- the bridge reads `halted` and `reason` from its READ
    thread, and the store connection they would otherwise touch belongs to
    another thread entirely."""
    root = tmp_path / "engagement"
    secure_mkdir(root)
    conn = db_mod.connect(root / "hx.db")
    db_mod.init_schema(conn)
    conn.execute("INSERT INTO engagement(id, name, client, created_us, status)"
                 " VALUES('e-1','Example','Example Ltd',1,'active')")
    conn.execute("INSERT INTO run(id, engagement_id, kind, safety_profile,"
                 " started_us, status)"
                 " VALUES('r-1','e-1','manual','production',1700000000000000,"
                 "'running')")
    yield root, conn
    conn.close()


@pytest.fixture
def halt(store):
    """The sentinel every server here is built over.

    `BridgeServer` refuses to construct without one, deliberately -- the same
    call HxExtension makes about `-Dhx.halt_sentinel`, for the same field and
    the same reason. A test with no engagement of its own supplies one in
    tmp_path, which is exactly the discipline that requirement imposes.
    """
    root, conn = store
    return halt_mod.OperatorHalt(root, conn)


@pytest.fixture
def srv(tmp_path, halt):
    s = server.BridgeServer(tmp_path / "b.sock", engagement_id="e-1",
                            operator_halt=halt)
    s.start()
    yield s
    s.stop()


def _client(path):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(str(path))
    # Every blocking read in this file -- thirteen of them, bare c.recv() and
    # codec.FrameReader(c).read() alike -- goes through this helper. Without a
    # timeout, a server that never answers HANGS the run rather than failing
    # it: deleting the SO_PEERCRED uid check was measured wedging pytest
    # indefinitely. Sabotage is this project's review method, so a defect that
    # cannot report itself is a real cost.
    c.settimeout(5)
    return c


def _never_served(c, frame: bytes) -> bytes | None:
    """Send `frame` and collect what came back. b"" is "nothing, ever".

    None means the socket was STILL OPEN when the read timed out, which is a
    different and much worse answer -- the bridge never replies to a hello
    with a frame, so an open socket is one nothing refused.

    THREE ENDINGS ALL MEAN "REFUSED", AND THIS TEST MUST NOT CARE WHICH:

      * a clean FIN, and recv answers b"".
      * an RST, and recv raises ConnectionResetError. Linux sends one when a
        socket is closed with unread data still in its receive buffer, which
        is exactly what BridgeServer._serve does to a foreign uid: it closes
        WITHOUT EVER READING the frame.
      * EPIPE on the WRITE. The server closed before this frame could be
        written at all -- the refusal arriving sooner, not failing to arrive.

    THE THIRD ONE IS A REAL RACE AND IT MADE THIS FILE'S ONE SECURITY TEST
    FLAKY: two failures in ~19 full-suite runs against 25/25 in isolation, on
    a file that wave had not touched. It was never the bridge. The main thread
    releases the GIL inside connect(), and whether it gets it back before the
    accept-loop thread runs the uid check and closes decides which of the two
    orderings a run gets. MEASURED, same client sequence, one server:

        contending threads   0 ->   0/500 EPIPE   (why isolation never fails)
        contending threads   2 -> 163/500 EPIPE
        contending threads   8 -> 180/500 EPIPE

    A full-suite run is the contended case. So `sendall` raising here is not
    the failure -- it is the guard being fast -- and a test that reddens on it
    trains everyone to re-run instead of look. The failure is the connection
    still being open, or bytes coming back, and those are what the caller
    asserts on.
    """
    try:
        c.sendall(frame)
    except (BrokenPipeError, ConnectionResetError):
        return b""
    try:
        return c.recv(4096)
    except ConnectionResetError:
        return b""
    except TimeoutError:
        return None


def _connected(srv):
    """Drive srv to state 'connected' and return the live client socket."""
    c = _client(srv.socket_path)
    c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                            "pid": 1, "burp_version": "x",
                            "instance_id": "i-1", "engagement_id": "e-1"}))
    deadline = time.time() + 5
    while srv.state != "connected" and time.time() < deadline:
        time.sleep(0.005)
    assert srv.state == "connected"
    return c


def test_a_bridge_cannot_be_built_without_a_sentinel(tmp_path):
    """S4 promises three kill paths, and an opt-in third path is not a promise.

    Optional, `operator_halt` made the whole durable halt opt-in. Measured
    with the argument simply left off:

        sentinel on disk: True   operator_halt attr: None
        SEND REACHED THE WIRE with a HALTED sentinel present
        after server.halt(): agent_action rows = 0

    A HALTED file placed by hand -- S4's named "the socket is dead, stop by
    hand" path -- did not stop send(), and halt() wrote neither sentinel nor
    audit row. The extension still refused via its own poller, so S4's
    ENFORCEMENT invariant held; what was lost was durability and the
    harness-side refusal.

    The Java side made the opposite call for the same field and said why:
    HxExtension refuses to initialise without `-Dhx.halt_sentinel` because an
    extension that went live without one "would have two of the three paths
    spec s4 promises, silently". This is that refusal, on this side.
    """
    with pytest.raises(TypeError, match="operator_halt"):
        server.BridgeServer(tmp_path / "b.sock", engagement_id="e-1")
    # And an explicit None, which is the same fail-open with a keystroke in
    # front of it. The signature cannot catch that one; the constructor does,
    # and it does it before start() rather than at the first send.
    with pytest.raises(server.BridgeError, match="operator_halt is required"):
        server.BridgeServer(tmp_path / "b.sock", engagement_id="e-1",
                            operator_halt=None)


def test_socket_and_directory_permissions(tmp_path, halt):
    s = server.BridgeServer(tmp_path / "sub" / "b.sock", engagement_id="e-1",
                            operator_halt=halt)
    s.start()
    try:
        assert stat.S_IMODE(s.socket_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(s.socket_path.parent.stat().st_mode) == 0o700
    finally:
        s.stop()


def test_stop_unlinks_the_socket(tmp_path, halt):
    s = server.BridgeServer(tmp_path / "b.sock", engagement_id="e-1",
                            operator_halt=halt)
    s.start()
    path = s.socket_path
    assert path.exists()
    s.stop()
    assert not path.exists()


def test_refuses_to_start_if_the_path_already_exists(tmp_path, halt):
    p = tmp_path / "b.sock"
    p.write_text("squatter")
    s = server.BridgeServer(p, engagement_id="e-1", operator_halt=halt)
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
        # configure() must not race the accept-loop thread's processing of
        # the hello: without this wait, a thread scheduled early enough sees
        # state == "waiting", raises BridgeError internally (silently, since
        # nothing joins it before the assertion), and the main thread then
        # blocks forever below waiting for a request frame that was never
        # sent. Reproduced: roughly 1 run in 10 hung indefinitely.
        deadline = time.time() + 5
        while srv.state != "connected" and time.time() < deadline:
            time.sleep(0.01)
        assert srv.state == "connected"
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
        # See test_configure_round_trip_returns_an_epoch: without waiting for
        # the hello to land, this races the accept-loop thread and can hang.
        deadline = time.time() + 5
        while srv.state != "connected" and time.time() < deadline:
            time.sleep(0.01)
        assert srv.state == "connected"
        result = {}

        def do_configure():
            # The test never sends a "configured" ack, and closes the
            # connection in its finally below. _reset()'s wake-on-disconnect
            # (round 1) now surfaces that immediately as BridgeError, where
            # it previously just blocked for the full 10s timeout unnoticed --
            # that is the desired prompt-wakeup behaviour, not a bug. Catch it
            # here rather than let it become an unhandled thread exception.
            try:
                srv.configure({"scope.include": ["https://a/*"]},
                              scope_sha256="x", profile="production")
            except server.BridgeError as exc:
                result["error"] = exc

        t = threading.Thread(target=do_configure)
        t.start()
        header, _ = codec.FrameReader(c).read()
        assert isinstance(header["id"], int) and header["id"] > 0
        assert isinstance(header["deadline_us"], int)
        assert header["deadline_us"] > time.time_ns() // 1000
    finally:
        c.close()
        t.join(timeout=5)
        assert not t.is_alive(), "do_configure thread never finished"
        assert "error" in result, "closing without an ack must raise BridgeError"


def test_configure_before_hello_is_refused(srv):
    """What the precondition holds back is real, not hypothetical: _serve()
    assigns self._conn BEFORE the hello is read, so an un-helloed peer is a
    perfectly good socket to write to. Driven directly, it received the
    engagement id, the scope_sha256 and every scope pattern.

    `match=` therefore names the WHOLE message. "not connected" on its own is
    also what _send() raises when self._conn is None, so with the precondition
    deleted this test still passed -- on the wrong raise, from two frames
    further down, after the scope had already gone out. The peer-receives-
    nothing assertion is the one that cannot be satisfied by the wrong raise
    at all.
    """
    c = _client(srv.socket_path)
    try:
        # Wait for the server to have accepted and stored the socket: that is
        # precisely the window in which only the precondition stands between a
        # caller and a scope on the wire.
        deadline = time.time() + 5
        while srv._conn is None and time.time() < deadline:
            time.sleep(0.005)
        assert srv._conn is not None, "the server should have accepted the connection"
        assert srv.state == "waiting", "no hello has been sent"

        with pytest.raises(server.BridgeError, match="cannot configure before hello"):
            srv.configure({"scope.include": ["https://SECRET/*"]},
                          scope_sha256="deadbeef", profile="production")

        # Nothing at all may have reached the peer. A short timeout, not the
        # helper's 5s: this asserts an absence, so the wait is pure cost.
        c.settimeout(0.5)
        with pytest.raises(TimeoutError):
            c.recv(4096)
    finally:
        c.close()


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
    # Without this, the test passes even when hello handling is completely
    # broken: state never leaves "waiting", so the second poll's precondition
    # is already true. Verified by sabotage -- it passed in 5.22s with hello
    # handling entirely disabled.
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


def test_configure_ack_then_immediate_disconnect_ends_in_deny_all(srv):
    """Critical, fix round 1: configure() wrote self.state = "configured" and
    self.config_epoch from the caller's thread with no ordering against
    _reset() on the accept thread. A peer that acks configure and immediately
    disconnects could leave state="configured" with no peer attached at all --
    falsifying DENY-ALL as the terminal state. Reproduced 59/60 runs before
    the generation-token fix, so this loops enough times to be meaningful.
    """
    for _ in range(60):
        c = _client(srv.socket_path)
        try:
            c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                                    "pid": 1, "burp_version": "x",
                                    "instance_id": "i-1", "engagement_id": "e-1"}))
            deadline = time.time() + 5
            while srv.state != "connected" and time.time() < deadline:
                time.sleep(0.01)
            assert srv.state == "connected"

            result = {}

            def do_configure():
                try:
                    result["epoch"] = srv.configure(
                        {"scope.include": ["https://a/*"]},
                        scope_sha256="x", profile="production",
                    )
                except server.BridgeError as exc:
                    result["error"] = exc

            t = threading.Thread(target=do_configure)
            t.start()

            header, _ = codec.FrameReader(c).read()
            c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                    "config_epoch": 1}))
            c.close()
            t.join(timeout=5)
            assert not t.is_alive(), "do_configure thread never finished"

            deadline = time.time() + 5
            while srv.state != "waiting" and time.time() < deadline:
                time.sleep(0.01)
            assert srv.state == "waiting", (
                "a peer that acked configure and vanished must not leave the "
                f"bridge looking configured (result={result!r})"
            )
            assert srv.config_epoch == 0
        finally:
            try:
                c.close()
            except OSError:
                pass


def test_late_reply_after_timeout_does_not_leak_into_replies(srv):
    """Important, fix round 1: _deliver used to record a reply before checking
    whether anyone was waiting for it. A reply that arrives after its caller
    gave up left an entry nothing ever collects -- unbounded growth on a
    bridge meant to run for a whole engagement."""
    c = _client(srv.socket_path)
    try:
        c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1", "pid": 1,
                                "burp_version": "x", "instance_id": "i-1",
                                "engagement_id": "e-1"}))
        deadline = time.time() + 5
        while srv.state != "connected" and time.time() < deadline:
            time.sleep(0.01)
        assert srv.state == "connected"

        with pytest.raises(server.BridgeError, match="no reply"):
            srv._request({"v": 1, "t": "configure", "engagement_id": "e-1"},
                         timeout=0.1)

        # Only now does the peer read and ack the request the server already
        # gave up waiting on.
        header, _ = codec.FrameReader(c).read()
        c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                "config_epoch": 1}))
        time.sleep(0.3)  # give the late reply a chance to be (mis)handled
        assert srv._replies == {}, "a reply nobody awaits must not be recorded"
    finally:
        c.close()


def test_so_peercred_rejects_a_foreign_uid(srv, monkeypatch):
    """The one security-critical branch in the file, previously uncovered.
    Cannot actually connect as another uid in a test, so fake the credential
    lookup SO_PEERCRED reports.

    THIS TEST WAS FLAKY -- twice in ~19 full-suite runs, 25/25 in isolation --
    and the cause was here, not in the bridge. See _never_served below, which
    is where the race is written down and where it is now absorbed. The
    server's behaviour was correct in both orderings the race produces; it
    was this file that could only cope with one of them.
    """
    real_getsockopt = socket.socket.getsockopt

    def fake_getsockopt(self, level, optname, buflen=0):
        if optname == socket.SO_PEERCRED:
            return struct.pack("3i", 12345, os.getuid() + 1, os.getgid())
        return real_getsockopt(self, level, optname, buflen)

    monkeypatch.setattr(socket.socket, "getsockopt", fake_getsockopt)

    c = _client(srv.socket_path)
    try:
        hello = codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                              "pid": os.getpid(), "burp_version": "x",
                              "instance_id": "i-1", "engagement_id": "e-1"})
        served = _never_served(c, hello)
        assert served == b"", (
            f"a foreign uid must never be served (state {srv.state!r}): "
            + (f"the server answered {served!r}" if served is not None else
               "the connection was STILL OPEN when the read timed out. The "
               "bridge never answers a hello with a frame, so a socket left "
               "open is one the uid check did not close"))

        # Not merely "no bytes came back". These two are the assignment the
        # uid check `return`s in front of -- see BridgeServer._serve -- so
        # they say the connection was REFUSED rather than merely quiet, which
        # a shut-down server would also be.
        assert (srv.peer_uid, srv.peer_pid) == (None, None), (
            "a foreign peer was recorded as this bridge's peer: "
            f"uid={srv.peer_uid} pid={srv.peer_pid}")
        assert srv.state == "waiting"
        assert srv.hello is None, "a foreign uid's hello was accepted"
    finally:
        c.close()


def test_configure_refuses_to_commit_when_a_reset_ran_in_the_gap(srv):
    """The whole point of the guard, deterministically: no threads, no sleeps.
    The stub performs the disconnect inside the window between _request()
    returning and configure()'s commit."""
    c = _connected(srv)
    try:
        def stub_request(header, body=b""):
            srv._reset(srv._generation)
            return {"v": 1, "t": "configured", "id": 1, "config_epoch": 7}
        srv._request = stub_request

        with pytest.raises(server.BridgeError,
                           match="peer disconnected before configure completed"):
            srv.configure({"scope.include": ["https://a/*"]},
                          scope_sha256="x", profile="production")
        assert srv.state == "waiting"
        assert srv.config_epoch == 0
    finally:
        c.close()


def test_configure_refuses_to_commit_when_the_socket_slot_was_refilled(srv):
    """Deliberately white-box, and the only test that isolates the generation
    token. It refills self._conn without going through accept(), so the
    `_conn is None` clause cannot fire and only `gen != self._generation`
    is left to catch the stale commit. Delete `self._generation += 1` from
    _reset() and this test fails; that is what it exists for."""
    c = _connected(srv)
    successor, other = socket.socketpair()
    try:
        def stub_request(header, body=b""):
            srv._reset(srv._generation)
            srv._conn = successor          # slot refilled: _conn is NOT None
            return {"v": 1, "t": "configured", "id": 1, "config_epoch": 7}
        srv._request = stub_request

        with pytest.raises(server.BridgeError,
                           match="peer disconnected before configure completed"):
            srv.configure({"scope.include": ["https://a/*"]},
                          scope_sha256="x", profile="production")
        assert srv.state == "waiting"
        assert srv.config_epoch == 0
    finally:
        srv._conn = None
        successor.close()
        other.close()
        c.close()


def test_reset_advances_the_generation_it_guards_on(srv):
    """The invariant is internal, so test it internally rather than pretend a
    black-box test can see it."""
    g0 = srv._generation
    srv._reset(g0)
    assert srv._generation > g0, "a real reset must advance the generation"

    g1 = srv._generation
    srv.state = "configured"
    srv.config_epoch = 9
    srv._reset(g0)                          # stale token: must be a no-op
    assert srv._generation == g1
    assert srv.state == "configured" and srv.config_epoch == 9


def test_halt_and_resume_refuse_to_commit_after_a_reset_in_the_gap(srv):
    """halt()/resume() have the same send-then-mutate shape as configure(),
    so they get the same test. Without this, the guard on them is unexercised
    by the whole suite."""
    for method, message in (
        (lambda: srv.halt("operator"), "peer disconnected before halt completed"),
        (lambda: srv.resume(), "peer disconnected before resume completed"),
    ):
        c = _connected(srv)
        try:
            def stub_send(header, body=b""):
                srv._reset(srv._generation)
            srv._send = stub_send

            with pytest.raises(server.BridgeError, match=message):
                method()
            assert srv.state == "waiting"
        finally:
            del srv._send          # fall back to the real bound method
            c.close()
            # The first pass really arms the durable halt -- operator_halt is
            # required now, so `srv` has a live one and halt() arms it before
            # the send it is about to fail on. The second pass would then be
            # met by _reassert_halt on its hello and never see "connected",
            # which is the halt working as designed and not what THIS test is
            # about: the subject here is the send-then-mutate guard on the
            # bridge. Durability has its own tests, two of them directly
            # below the send path section.
            srv.operator_halt.resume()


def test_halt_and_resume_commit_on_the_happy_path(srv):
    c = _connected(srv)
    try:
        srv.halt("operator asked")
        assert srv.state == "halted"
        reader = codec.FrameReader(c)
        header, _ = reader.read()
        assert header["t"] == "halt" and header["reason"] == "operator asked"

        srv.resume()
        assert srv.state == "connected"     # no config_epoch yet
        header, _ = reader.read()
        assert header["t"] == "resume"
    finally:
        c.close()


def test_configure_never_leaves_a_lying_state_under_stress(srv, monkeypatch):
    """Round 2: the generation token read _generation as a guard but never
    advanced it, so it only detected "a NEW connection superseded an old
    one". It could not detect THIS connection resetting between _request()
    returning and configure()'s commit -- the caller still saw
    gen == self._generation and clobbered the "waiting" _reset() had just
    written. The natural-timing test above measured 0/60 for this because the
    accept thread happens to win that inner race on this machine -- favourable
    scheduling, not a closed gap. This closes the window instead of relying
    on timing: it delays configure()'s resumption after
    _request() returns, giving the accept thread's _reset() every chance to
    run to completion first, and asserts configure() detects it rather than
    silently committing over it.
    """
    real_request = server.BridgeServer._request

    def delayed_request(self, *args, **kwargs):
        reply = real_request(self, *args, **kwargs)
        time.sleep(0.08)  # matches the ~80ms window the reviewer used
        return reply

    monkeypatch.setattr(server.BridgeServer, "_request", delayed_request)

    for _ in range(20):
        c = _client(srv.socket_path)
        try:
            c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                                    "pid": 1, "burp_version": "x",
                                    "instance_id": "i-1", "engagement_id": "e-1"}))
            deadline = time.time() + 5
            while srv.state != "connected" and time.time() < deadline:
                time.sleep(0.01)
            assert srv.state == "connected"

            result = {}

            def do_configure():
                try:
                    result["epoch"] = srv.configure(
                        {"scope.include": ["https://a/*"]},
                        scope_sha256="x", profile="production",
                    )
                except server.BridgeError as exc:
                    result["error"] = exc

            t = threading.Thread(target=do_configure)
            t.start()

            header, _ = codec.FrameReader(c).read()
            c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                    "config_epoch": 1}))
            # Close now, while do_configure is still asleep inside the
            # widened window: the accept thread's _reset() must run and
            # complete (including advancing the generation) well before
            # do_configure wakes up to commit.
            c.close()
            t.join(timeout=5)
            assert not t.is_alive(), "do_configure thread never finished"

            assert "error" in result, (
                "configure() must detect a disconnect that happened during "
                f"its widened commit window, not silently succeed (result={result!r})"
            )
            # Whichever mechanism fires, the forbidden outcome is the same:
            # state that claims a peer the server no longer has.
            assert not (srv.state == "configured" and srv._conn is None), (
                f"lying state after a disconnect mid-configure (result={result!r})"
            )

            deadline = time.time() + 5
            while srv.state != "waiting" and time.time() < deadline:
                time.sleep(0.01)
            assert srv.state == "waiting", (
                f"a disconnect during configure()'s commit window must not "
                f"leave the bridge looking configured (result={result!r})"
            )
            assert srv.config_epoch == 0
        finally:
            try:
                c.close()
            except OSError:
                pass


def test_an_error_reply_to_configure_reports_what_the_peer_said(srv):
    c = _connected(srv)
    try:
        out = {}

        def go():
            try:
                srv.configure({"scope.include": ["https://a/*"]},
                              scope_sha256="x", profile="production")
            except server.BridgeError as exc:
                out["err"] = str(exc)

        t = threading.Thread(target=go)
        t.start()
        header, _ = codec.FrameReader(c).read()
        c.sendall(codec.encode({"v": 1, "t": "error", "id": header["id"],
                                "class": "engagement_mismatch",
                                "detail": "e-1 != SOMEONE-ELSE"}))
        t.join(timeout=5)
        assert not t.is_alive()

        assert "engagement_mismatch" in out["err"], out
        assert "SOMEONE-ELSE" in out["err"], out
        assert "without a config_epoch" not in out["err"], out
    finally:
        c.close()


def test_a_refused_reconfigure_returns_this_side_to_deny_all(srv):
    """The extension answers a refused configure by dropping to DENY-ALL at
    epoch 0 -- it discards the scope it was already holding. If this side went
    on reporting state='configured' epoch=1 the two ends of the bridge would
    disagree about whether anything may be sent, and this is the end operators
    and the CLI read."""
    c = _connected(srv)
    reader = codec.FrameReader(c)
    out = {}

    def configure_into(key):
        def run():
            try:
                out[key] = srv.configure({"scope.include": ["https://a/*"]},
                                         scope_sha256="x", profile="production")
            except server.BridgeError as exc:
                out[key] = exc
        return run

    try:
        # A first configure that IS acknowledged: epoch 1, state 'configured'.
        t = threading.Thread(target=configure_into("first"))
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                "config_epoch": 1}))
        t.join(timeout=5)
        assert not t.is_alive()
        assert out["first"] == 1, out
        assert srv.state == "configured"
        assert srv.config_epoch == 1

        # The second is refused. An operator NARROWING scope with a key the
        # installed extension predates is the likeliest way to land here, so
        # the wider epoch-1 scope is exactly what must not survive.
        t = threading.Thread(target=configure_into("second"))
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "error", "id": header["id"],
                                "class": "bad_config",
                                "detail": "unknown key scope.exclude_ports"}))
        t.join(timeout=5)
        assert not t.is_alive()
        assert isinstance(out["second"], server.BridgeError), out
        assert "bad_config" in str(out["second"]), out

        assert srv.state == "connected", (
            "the peer is at DENY-ALL after refusing the configure; this side "
            f"must not go on claiming {srv.state!r}"
        )
        assert srv.config_epoch == 0, srv.config_epoch
    finally:
        c.close()


# ---- register_identity ------------------------------------------------

# `register_identity` blocks waiting for the peer's reply, exactly like
# `configure()` above. See test_configure_round_trip_returns_an_epoch for the
# shape this borrows and the race it guards against: calling it inline and
# then trying to read the frame off the same thread deadlocks, since nothing
# is left to send the reply. `_connected` already drives past the hello
# handshake before handing back the socket, which is what keeps these three
# clear of that race -- `_conn` is set and `state` is "connected" before the
# thread below ever calls in.


def test_registering_an_identity_sends_an_identity_frame(srv):
    c = _connected(srv)
    reader = codec.FrameReader(c)
    try:
        result = {}

        def do_register():
            try:
                srv.register_identity(
                    identity.Resolved(id="user", header="Cookie",
                                      value="session=abc", generation=1),
                    origins=("https://app.test",))
                result["ok"] = True
            except server.BridgeError as exc:
                result["error"] = exc

        t = threading.Thread(target=do_register)
        t.start()

        header, body = reader.read()
        assert header["t"] == "identity"
        assert header["engagement_id"] == "e-1"
        assert isinstance(header["id"], int) and header["id"] > 0
        parsed = codec.parse_identity(body)
        assert parsed["identity_id"] == "user" and parsed["generation"] == 1
        assert parsed["inject"] == {"header": "Cookie", "value": "session=abc"}
        assert parsed["origins"] == ["https://app.test"]

        c.sendall(codec.encode({"v": 1, "t": "identity_registered",
                                "id": header["id"]}))
        t.join(timeout=5)
        assert not t.is_alive(), "do_register thread never finished"
        assert result.get("ok") is True, result
    finally:
        c.close()


def test_an_identity_frame_is_never_logged(srv, caplog):
    """The ONLY frame in this protocol whose payload is a secret. The bridge
    logs frame kinds and correlation ids elsewhere in this class (see
    test_a_refused_peer_is_counted_and_logged_rather_than_dropped_in_silence);
    a debug line added to this method that printed `resolved.value` is
    exactly how a live session cookie reaches a log file that outlives the
    engagement.
    """
    c = _connected(srv)
    reader = codec.FrameReader(c)
    try:
        result = {}

        def do_register():
            try:
                srv.register_identity(
                    identity.Resolved(id="user", header="Cookie",
                                      value="session=SUPERSECRET",
                                      generation=1),
                    origins=("https://app.test",))
                result["ok"] = True
            except server.BridgeError as exc:
                result["error"] = exc

        with caplog.at_level("DEBUG"):
            t = threading.Thread(target=do_register)
            t.start()
            header, _ = reader.read()
            c.sendall(codec.encode({"v": 1, "t": "identity_registered",
                                    "id": header["id"]}))
            t.join(timeout=5)

        assert not t.is_alive(), "do_register thread never finished"
        assert result.get("ok") is True, result
        assert "SUPERSECRET" not in caplog.text
        assert "identity" in caplog.text, "the frame KIND is still loggable"
    finally:
        c.close()


def test_a_refused_identity_frame_raises(srv):
    c = _connected(srv)
    reader = codec.FrameReader(c)
    try:
        result = {}

        def do_register():
            try:
                srv.register_identity(
                    identity.Resolved(id="user", header="Cookie", value="v",
                                      generation=1),
                    origins=("https://app.test",))
            except server.BridgeError as exc:
                result["error"] = exc

        t = threading.Thread(target=do_register)
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "error", "id": header["id"],
                                "class": "stale_generation",
                                "detail": "generation 1 is not above 3"}))
        t.join(timeout=5)
        assert not t.is_alive(), "do_register thread never finished"
        assert isinstance(result.get("error"), server.BridgeError), result
        assert result["error"].error_class == "stale_generation"
        assert "stale_generation" in str(result["error"])
    finally:
        c.close()


def test_an_unexpected_ack_shape_is_a_refusal_not_a_silent_success(srv):
    """Finding 1 of the Task 3 review, and the direction the gap ran.

    `register_identity` used to test only for `t == "error"` and return on
    everything else, so a reply of any other shape -- a `result` frame from a
    confused peer, an ack for a frame type this side does not know -- read as
    "the credential is now live in the extension". Every probe after it would
    then issue believing it carried a session it does not have, and answer
    `clean` about the logged-out view of an authenticated application: the
    exact confusion this whole feature exists to remove, arrived at by
    agreeing with a peer instead of by having no identity at all.

    `send()` has always been strict about its reply type. This is the same
    rule on the one frame whose payload is a live credential.
    """
    c = _connected(srv)
    reader = codec.FrameReader(c)
    try:
        result = {}

        def do_register():
            try:
                srv.register_identity(
                    identity.Resolved(id="user", header="Cookie", value="v",
                                      generation=1),
                    origins=("https://app.test",))
                result["returned"] = True
            except server.BridgeError as exc:
                result["error"] = exc

        t = threading.Thread(target=do_register)
        t.start()
        header, _ = reader.read()
        # A well-formed frame of the WRONG type: not an error, not the ack.
        c.sendall(codec.encode({"v": 1, "t": "result", "id": header["id"],
                                "status": 200, "outcome": "ok"}))
        t.join(timeout=5)
        assert not t.is_alive(), "do_register thread never finished"
        assert "returned" not in result, (
            "a `result` frame was accepted as a successful identity "
            "registration")
        assert isinstance(result.get("error"), server.BridgeError), result
        assert "result" in str(result["error"])
    finally:
        c.close()


def test_send_serialises_concurrent_writers(srv):
    """_send() wrote the socket with no mutex at all, while its Java
    counterpart is a deliberate `private synchronized void send`. Two threads
    inside one sendall() splice two frames together on the wire and the peer
    then decodes neither -- and every write on this side is a control frame:
    halt, resume, configure.

    Deterministic rather than scheduler-dependent. The stand-in socket parks
    halfway through each write, which is exactly what a real sendall() does
    when the socket buffer fills mid-frame, and both writers meet at a barrier
    IF the code lets them be inside at once. Serialised, the first writer
    breaks the barrier on its timeout and the second sails straight through.
    """
    chunks: list[bytes] = []
    gate = threading.Barrier(2, timeout=0.5)
    state_lock_was_free = []

    class SplittingConn:
        def sendall(self, data):
            half = len(data) // 2
            chunks.append(data[:half])
            # Parked mid-frame. The state mutex must NOT be held here: this
            # lock has to be a separate one, or a blocking send stalls the
            # _deliver() that wakes the _request() waiting on this very frame.
            free = srv._lock.acquire(blocking=False)
            if free:
                srv._lock.release()
            state_lock_was_free.append(free)
            try:
                gate.wait()
            except threading.BrokenBarrierError:
                pass
            chunks.append(data[half:])

    srv._conn = SplittingConn()
    try:
        # Two frames of DIFFERENT lengths, so a spliced wire cannot decode by
        # luck: frame one's length prefix would then span frame two's bytes.
        writers = [
            threading.Thread(target=srv._send, args=(
                {"v": 1, "t": "halt", "reason": "a" * 200},)),
            threading.Thread(target=srv._send, args=(
                {"v": 1, "t": "resume"},)),
        ]
        for w in writers:
            w.start()
        for w in writers:
            w.join(timeout=10)
            assert not w.is_alive()

        assert all(state_lock_was_free), (
            "the send mutex must be separate from self._lock: holding the state "
            "mutex across a blocking sendall() stalls _deliver()"
        )

        wire = b"".join(chunks)
        first, _, consumed = codec.decode(wire)
        second, _, _ = codec.decode(wire[consumed:])
        assert {first["t"], second["t"]} == {"halt", "resume"}, (
            f"two writers spliced their frames together on the wire: {wire!r}"
        )
    finally:
        srv._conn = None


def test_a_configure_does_not_lift_a_halt(srv):
    """An operator halts BECAUSE the scope went wrong, then pushes the
    corrected scope -- the most likely next action there is. Writing
    state="configured" over "halted" here re-armed issuance with no `resume`
    on the wire, no log line, and both consoles reading "configured". Only
    resume() may lift a halt.

    The other half is just as load-bearing: the scope and the epoch must still
    commit. Narrowing scope during an emergency stop is exactly what an
    operator should be able to do, which is why "halted" stays in configure()'s
    accepted-state tuple rather than being refused outright. A configure
    re-authorises SCOPE, not ISSUANCE. The extension half of this lives in
    BridgeClientTest.aConfigureDoesNotLiftAHalt().
    """
    c = _connected(srv)
    reader = codec.FrameReader(c)
    out = {}

    def configure_into(key, pattern):
        def run():
            try:
                out[key] = srv.configure({"scope.include": [pattern]},
                                         scope_sha256="x", profile="production")
            except server.BridgeError as exc:
                out[key] = exc
        return run

    try:
        t = threading.Thread(target=configure_into("first", "https://WIDE/*"))
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                "config_epoch": 1}))
        t.join(timeout=5)
        assert not t.is_alive()
        assert out["first"] == 1, out
        assert srv.state == "configured"

        srv.halt("scope was wrong")
        header, _ = reader.read()
        assert header["t"] == "halt"
        assert srv.state == "halted"

        # The corrected, NARROWER scope, pushed while halted.
        t = threading.Thread(target=configure_into("second", "https://NARROW/*"))
        t.start()
        header, body = reader.read()
        assert header["t"] == "configure"
        assert codec.parse_config_body(body)["scope.include"] == ["https://NARROW/*"]
        c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                "config_epoch": 2}))
        t.join(timeout=5)
        assert not t.is_alive()
        assert out["second"] == 2, out

        assert srv.state == "halted", (
            "a configure frame must not lift an operator halt; only resume() may"
        )
        assert srv.config_epoch == 2, (
            "the corrected scope must still commit -- narrowing scope during an "
            "emergency stop is exactly what an operator should be able to do"
        )

        # resume() is the frame that IS allowed to re-arm issuance, and it
        # returns to "configured" under the epoch-2 scope.
        srv.resume()
        header, _ = reader.read()
        assert header["t"] == "resume"
        assert srv.state == "configured"
        assert srv.config_epoch == 2
    finally:
        c.close()


def test_a_non_denying_configure_error_leaves_state_alone(srv):
    """engagement_mismatch and bad_frame answer error but leave the extension
    configured and live -- unlike bad_config and protocol_mismatch, which
    call denyAll() before answering. Resetting THIS side for those two would
    make it report state='connected', config_epoch=0 while the extension is
    still configured and sending: the reverse of the disagreement the reset
    exists to fix, and the more dangerous direction, since the operator's
    console would then say nothing may be sent while it can.

    Unreachable through a real client today -- a mismatched engagement_id is
    rejected at hello, and _request() always stamps deadline_us -- so this
    needs a version-skewed jar, the same scenario the plan names for
    bad_config. Reached here directly, the same way
    test_an_error_reply_to_configure_reports_what_the_peer_said reaches its
    own class string."""
    c = _connected(srv)
    reader = codec.FrameReader(c)
    out = {}

    def configure_into(key):
        def run():
            try:
                out[key] = srv.configure({"scope.include": ["https://a/*"]},
                                         scope_sha256="x", profile="production")
            except server.BridgeError as exc:
                out[key] = exc
        return run

    try:
        # A first configure that IS acknowledged: epoch 1, state 'configured'.
        t = threading.Thread(target=configure_into("first"))
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                "config_epoch": 1}))
        t.join(timeout=5)
        assert not t.is_alive()
        assert out["first"] == 1, out
        assert srv.state == "configured"
        assert srv.config_epoch == 1

        # A second configure is refused, but with a class the extension does
        # NOT deny for.
        t = threading.Thread(target=configure_into("second"))
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "error", "id": header["id"],
                                "class": "engagement_mismatch",
                                "detail": "e-1 != e-2"}))
        t.join(timeout=5)
        assert not t.is_alive()
        assert isinstance(out["second"], server.BridgeError), out
        assert "engagement_mismatch" in str(out["second"]), out

        assert srv.state == "configured", (
            "the extension is still configured and live after this class of "
            f"refusal; this side must not go on claiming {srv.state!r}"
        )
        assert srv.config_epoch == 1, srv.config_epoch
    finally:
        c.close()


# ---- the send path, the halted frame, and the durable halt ----------------


@pytest.fixture
def srv_with_halt(srv, halt, store):
    """The `srv` fixture, plus the halt and the store it was built over.

    These used to be a second server built by hand, from the days when
    `operator_halt` was optional and only this half of the file passed one.
    It is required now, so `srv` already has a real one and this is just the
    unpacking the twenty tests below read.
    """
    return srv, halt, store[1]


def _hello(c, engagement_id="e-1"):
    c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                            "pid": os.getpid(), "burp_version": "2026.7.3",
                            "instance_id": "i-1",
                            "engagement_id": engagement_id}))


def _await(predicate, message, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError(message)


def _configured(s, c):
    """hello plus one acknowledged configure. Returns the peer's reader."""
    reader = codec.FrameReader(c)
    _hello(c)
    _await(lambda: s.state == "connected", "the hello never landed")
    out = {}

    def go():
        try:
            out["epoch"] = s.configure(
                {"scope.include": ["https://app.example.test/*"]},
                scope_sha256="a" * 64, profile="production")
        except server.BridgeError as exc:
            out["err"] = exc

    t = threading.Thread(target=go)
    t.start()
    header, _ = reader.read()
    c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                            "config_epoch": 1}))
    t.join(timeout=5)
    assert out.get("epoch") == 1, out
    return reader


# Real bytes, loopback-shaped hostname, real header names. Nothing in this
# project has ever sent a request off the machine and these tests do not
# either: the peer is a socket in tmp_path.
REQ = b"GET /api/orders?page=2 HTTP/1.1\r\nHost: app.example.test\r\n\r\n"
RESP = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Set-Cookie: session={{observed:set-cookie}}; HttpOnly\r\n\r\n"
        b'{"orders":[]}')


def test_send_returns_the_result_frame_and_its_body(srv_with_halt):
    """The body is the point. A result frame's bytes are the redacted response
    -- the evidence about to be hashed into the blob store -- and _deliver()
    used to hand back the header alone and drop them."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        reader = _configured(s, c)
        out = {}
        t = threading.Thread(target=lambda: out.update(reply=s.send(
            {"target_host": "app.example.test", "target_port": 443,
             "tls": True, "identity_id": None}, REQ)))
        t.start()

        header, body = reader.read()
        assert header["t"] == "send"
        assert header["engagement_id"] == "e-1", (
            "S6: every send carries the engagement id and the extension "
            "refuses a mismatch"
        )
        assert header["target_host"] == "app.example.test"
        assert isinstance(header["id"], int) and header["id"] > 0
        assert header["deadline_us"] > time.time_ns() // 1000
        assert body == REQ, "the request bytes travel verbatim in the body"

        c.sendall(codec.encode({"v": 1, "t": "result", "id": header["id"],
                                "status": 200, "bytes": len(RESP), "ms": 42,
                                "outcome": "ok", "config_epoch": 1}, RESP))
        t.join(timeout=5)
        assert not t.is_alive()
        assert out["reply"]["status"] == 200
        assert out["reply"]["config_epoch"] == 1
        assert out["reply"][server.BridgeServer.BODY_KEY] == RESP
    finally:
        c.close()


def test_a_status_unreadable_result_reaches_the_store_unchanged(srv_with_halt):
    """The first consumer of a wire value added one commit before this task.

    S6 keeps `status` at the conservative sentinel 599 so S4's auto-halt
    counts it as an error, and moves the distinction to `outcome`. The wire
    value and exchange.outcome's value are deliberately the SAME STRING, so
    what this asserts is that no mapping layer appeared between them -- the
    frame's own outcome goes into the row, and the row can still be told
    apart from a peer that genuinely answered 599.

    The body on that frame says `HTTP/1.1 200 OK`, because that is the case
    that made the field necessary: eight interim heads then a 200.
    """
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        reader = _configured(s, c)
        out = {}
        t = threading.Thread(target=lambda: out.update(reply=s.send(
            {"target_host": "app.example.test"}, REQ)))
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "result", "id": header["id"],
                                "status": 599, "bytes": len(RESP), "ms": 42,
                                "outcome": "status_unreadable",
                                "config_epoch": 1}, RESP))
        t.join(timeout=5)
        reply = out["reply"]
        assert reply["status"] == 599
        assert reply["outcome"] == "status_unreadable"

        row_id = records.record_exchange(
            conn, run_id="r-1", method="GET",
            url="https://app.example.test/api/orders?page=2",
            status=reply["status"], outcome=reply["outcome"],
            req_blob="a" * 64, resp_blob="b" * 64, ms=reply["ms"],
            at_us=1700000000000000,
            resp_len=len(reply[server.BridgeServer.BODY_KEY]))
        row = conn.execute("SELECT status, outcome FROM exchange WHERE id=?",
                           (row_id,)).fetchone()
        assert (row["status"], row["outcome"]) == (599, "status_unreadable")
        assert b"HTTP/1.1 200 OK" in reply[server.BridgeServer.BODY_KEY], (
            "the exchange this outcome exists for is one whose own evidence "
            "contradicts its status"
        )
    finally:
        c.close()


def test_send_raises_the_peers_class_and_its_retry_hint(srv_with_halt):
    """S6 makes the class load-bearing for the agent: rate_limited means slow
    down and retry, the three *_denied classes mean the answer will not
    change, budget_exhausted means the run is over. A caller that only got a
    message string would have to parse English to tell them apart."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        reader = _configured(s, c)
        out = {}

        def go():
            try:
                s.send({"target_host": "app.example.test"}, REQ)
            except server.BridgeError as exc:
                out["err"] = exc

        t = threading.Thread(target=go)
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "error", "id": header["id"],
                                "class": "rate_limited",
                                "detail": "5 rps, 200000us to the next slot",
                                "retry_after_us": 200_000}))
        t.join(timeout=5)
        assert not t.is_alive()
        assert out["err"].error_class == "rate_limited"
        assert out["err"].retry_after_us == 200_000
        assert "5 rps" in str(out["err"])
        # And it is a class the store can actually record, which is the other
        # half of "denials are never silent".
        assert records.DENIAL_KIND[out["err"].error_class] == "rate"
    finally:
        c.close()


def test_send_never_retries(srv_with_halt):
    """S6: a replayed state-changing request is worse than a failed one. One
    call, one frame on the wire, whatever the answer was."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        reader = _configured(s, c)
        out = {}

        def go():
            try:
                s.send({"target_host": "app.example.test"}, REQ)
            except server.BridgeError as exc:
                out["err"] = exc

        t = threading.Thread(target=go)
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "error", "id": header["id"],
                                "class": "transport_error",
                                "detail": "connection reset"}))
        t.join(timeout=5)
        assert out["err"].error_class == "transport_error"

        # Nothing else may arrive. A short timeout, not the helper's 5s: this
        # asserts an absence, so the wait is pure cost.
        c.settimeout(0.5)
        with pytest.raises(TimeoutError):
            reader.read()
    finally:
        c.close()


def test_an_in_flight_send_fails_with_bridge_lost(srv_with_halt):
    """S6 names bridge_lost as distinct from timeout: the peer went away, the
    request may or may not have been issued, and nothing may replay it."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    reader = _configured(s, c)
    out = {}

    def go():
        try:
            s.send({"target_host": "app.example.test"}, REQ)
        except server.BridgeError as exc:
            out["err"] = exc

    t = threading.Thread(target=go)
    t.start()
    reader.read()          # the send frame is on the wire and unanswered
    c.close()
    t.join(timeout=5)
    assert not t.is_alive(), "the caller was left blocked on a dead peer"
    assert out["err"].error_class == "bridge_lost"


def test_a_send_nobody_answers_fails_with_timeout(srv_with_halt):
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        _configured(s, c)
        with pytest.raises(server.BridgeError) as exc:
            s.send({"target_host": "app.example.test"}, REQ, timeout=0.2)
        assert exc.value.error_class == "timeout", (
            "a peer that is alive and slow is not a peer that vanished"
        )
        assert exc.value.retry_after_us is None
    finally:
        c.close()


def test_send_before_configure_never_reaches_the_wire(srv_with_halt):
    """DENY-ALL is the initial state on both sides. The extension would refuse
    this too -- but a request that was never framed cannot be issued by a
    version-skewed jar either."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        _hello(c)
        _await(lambda: s.state == "connected", "the hello never landed")
        with pytest.raises(server.BridgeError) as exc:
            s.send({"target_host": "app.example.test"}, REQ)
        assert exc.value.error_class == "not_configured"

        c.settimeout(0.5)
        with pytest.raises(TimeoutError):
            c.recv(4096)
    finally:
        c.close()


def test_send_refuses_a_caller_supplied_engagement_id(srv_with_halt):
    """Client A's traffic must never land in client B's store, and the id on
    the frame is what the extension checks. A caller able to overwrite it
    would be addressing whichever extension answered."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        _configured(s, c)
        with pytest.raises(server.BridgeError, match="engagement_id"):
            s.send({"target_host": "app.example.test",
                    "engagement_id": "SOMEONE-ELSE"}, REQ)
    finally:
        c.close()


@pytest.mark.parametrize("key,value", [
    ("v", 99), ("t", "halt"), ("id", 1), ("deadline_us", 1),
    ("engagement_id", "SOMEONE-ELSE"),
])
def test_send_refuses_every_key_it_stamps_itself(srv_with_halt, key, value):
    """`**req` is spliced over the frame this method builds, so a caller's key
    WINS. Without the guard, `t` alone turns a send into a halt frame the
    extension acts on and nobody correlates, `v` gets answered
    protocol_mismatch and drops the channel, and `id` collides with a live
    correlation id so one of the two callers collects the other's reply.

    Refused rather than silently overwritten: a caller who set one of these
    believed something would happen, and quietly doing something else is how
    a scan ends up addressing an extension nobody meant to address.
    """
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        _configured(s, c)
        with pytest.raises(server.BridgeError) as exc:
            s.send({"target_host": "app.example.test", key: value}, REQ)
        assert exc.value.error_class is None, (
            "a malformed call is a harness bug, not a denial the store should "
            "file a row for"
        )
        assert key in str(exc.value)
        # And nothing reached the wire: the guard runs before _request().
        c.settimeout(0.5)
        with pytest.raises(TimeoutError):
            c.recv(4096)
    finally:
        c.close()


def test_a_halted_frame_stops_issuance_and_aborts_the_run(srv_with_halt):
    """S6's unsolicited `halted` frame, {reason, host, window}, no id. Without
    it an auto-halt is invisible until the next send fails and
    `run.status = aborted` has no stop_reason to record.

    THIS TEST IS THE REFERENCE HARNESS. Plan 4's tool layer copies the shape
    of the `on_halted` handling below, so the shape has to be the safe one.

    It used to call `abort_run` and stop there, and `abort_run` alone does not
    survive the connection the frame arrived on. Measured against a live
    bridge with only that call:

        after the halted frame:  state='halted'   operator_halt.halted=False
        after _reset():          state='waiting'  operator_halt.halted=False
        next send refused as 'not_configured' -- DENY-ALL, not the halt
        run.status='aborted'  <- the only survivor, and nothing on the send
                                 path consults it

    So a reconnect and a fresh configure re-armed issuance after an auto-halt.
    That the `halted` arm does not make the stop durable by itself is
    defensible and is NOT changed here -- S4 scopes durability to an OPERATOR
    halt, and the arm's own comment defers it. What is fixed is the pattern
    this test hands to Plan 4: the harness calls `oh.halt()` beside
    `abort_run`, and the assertions below fail if that line is ever dropped.
    """
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        _configured(s, c)
        seen = []
        # The callback runs on the READ THREAD, so it may not touch this
        # store's connection: it belongs to this thread. Hand the frame over
        # and do the writing here -- which is what a harness must do too.
        s.on_halted = seen.append

        c.sendall(codec.encode({"v": 1, "t": "halted",
                                "reason": "5xx rate 0.40",
                                "host": "app.example.test",
                                "window": "50 requests / 37s"}))
        _await(lambda: s.state == "halted", "the halted frame was ignored")
        _await(lambda: seen, "on_halted never fired")

        frame = seen[0]
        assert s.last_halted == frame, (
            "a harness with no callback installed still has to be able to see "
            "why issuance stopped"
        )
        stop_reason = (f"{frame['reason']} on {frame['host']} "
                       f"({frame['window']})")
        assert records.abort_run(conn, run_id="r-1", at_us=1700000000900000,
                                 stop_reason=stop_reason) is True
        row = conn.execute("SELECT status, stop_reason FROM run WHERE id='r-1'"
                           ).fetchone()
        assert row["status"] == "aborted"
        assert row["stop_reason"] == ("5xx rate 0.40 on app.example.test "
                                      "(50 requests / 37s)")
        # The line that makes the stop outlive this connection. `abort_run`
        # writes the run's epitaph; only this writes the sentinel and the row
        # the next Burp start reads. Both, or the auto-halt lasts exactly as
        # long as the socket it arrived on.

        oh.halt(f"target distress: {stop_reason}")

        with pytest.raises(server.BridgeError) as exc:
            s.send({"target_host": "app.example.test"}, REQ, timeout=0.5)
        assert exc.value.error_class == "halted"

        # And the same refusal after the connection goes away, which is what
        # made the missing line matter: `state` is back to DENY-ALL and a
        # configure would lift that, but the sentinel is what send() consults
        # first. Without oh.halt() above this is 'not_configured' -- a refusal
        # the next configure clears.
        s._reset()
        assert s.state == "waiting"
        with pytest.raises(server.BridgeError) as exc:
            s.send({"target_host": "app.example.test"}, REQ, timeout=0.5)
        assert exc.value.error_class == "halted", (
            "an auto-halt the harness recorded must still refuse after the "
            f"connection it arrived on is gone; this was {exc.value.error_class!r}"
        )
        assert oh.sentinel_path.exists()
        assert halt_mod.OperatorHalt(oh.engagement_dir, conn).halted is True, (
            "the next Burp start reads the store and the file; run.status="
            "'aborted' is not something the send path consults"
        )
    finally:
        c.close()


def test_a_halted_callback_that_throws_drops_to_deny_all(srv_with_halt):
    """The callback is what makes an auto-halt durable. If it threw, nothing
    was recorded, and carrying on beside a peer whose stop nobody wrote down
    is the one thing DENY-ALL exists to prevent."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        _configured(s, c)

        def boom(header):
            raise RuntimeError("the store is gone")

        s.on_halted = boom
        c.sendall(codec.encode({"v": 1, "t": "halted", "reason": "5xx rate 0.40",
                                "host": "app.example.test",
                                "window": "50 requests / 37s"}))
        _await(lambda: s.state == "waiting",
               "a throwing on_halted must close the connection")
        assert isinstance(s.halted_callback_error, RuntimeError)
    finally:
        c.close()


def test_a_durable_halt_is_reasserted_before_any_configure(srv_with_halt):
    """The task this whole module exists for.

    Two findings from the Plan 2 review meet here: a second `hello` erased the
    halt, and a halt did not survive a Burp restart -- precisely when someone
    has already hit stop. The assertion is about ORDER ON THE WIRE, not about
    state afterwards: a harness pushes scope from on_hello, so a re-assert
    that happened after that callback would leave the extension configured and
    armed for the length of a round trip.

    The second half is just as load-bearing. The configure still commits its
    scope and its epoch -- narrowing scope during an emergency stop is exactly
    what an operator should be able to do -- and it does NOT re-arm issuance.
    """
    s, oh, conn = srv_with_halt
    oh.halt("client called: stop everything")

    threads = []
    out = {}

    def push_scope():
        try:
            out["epoch"] = s.configure(
                {"scope.include": ["https://app.example.test/*"]},
                scope_sha256="b" * 64, profile="production")
        except server.BridgeError as exc:
            out["err"] = exc

    def on_hello(header):
        # Appended BEFORE start(): t.start() can be preempted the instant the
        # new thread runs, and the main thread below is fast enough to reach
        # threads[0] first. Measured as an IndexError under a full-suite run.
        t = threading.Thread(target=push_scope)
        threads.append(t)
        t.start()

    s.on_hello = on_hello

    c = _client(s.socket_path)
    try:
        reader = codec.FrameReader(c)
        _hello(c)

        first, _ = reader.read()
        assert first["t"] == "halt", (
            "a reconnecting extension must be told it is still halted BEFORE "
            f"it is handed a scope; the first frame it received was {first!r}"
        )
        assert first["reason"] == "client called: stop everything"

        second, body = reader.read()
        assert second["t"] == "configure"
        assert codec.parse_config_body(body)["scope.include"] == \
            ["https://app.example.test/*"]
        c.sendall(codec.encode({"v": 1, "t": "configured", "id": second["id"],
                                "config_epoch": 4}))
        threads[0].join(timeout=5)
        assert out.get("epoch") == 4, out

        assert s.state == "halted", (
            "a configure re-authorises scope, never issuance; only resume does"
        )
        assert s.config_epoch == 4, "the corrected scope must still commit"
        with pytest.raises(server.BridgeError) as exc:
            s.send({"target_host": "app.example.test"}, REQ, timeout=0.5)
        assert exc.value.error_class == "halted"
    finally:
        c.close()


def test_a_reset_never_clears_the_durable_halt(srv_with_halt):
    """_reset() returns this side to DENY-ALL, which is right, and it has no
    business touching the halt: the halt is not part of a connection's
    lifetime. It lives in OperatorHalt, on disk."""
    s, oh, conn = srv_with_halt
    oh.halt("operator pressed stop")
    s._reset()
    assert s.state == "waiting"
    assert oh.halted is True
    assert halt_mod.OperatorHalt(oh.engagement_dir, conn).halted is True


def test_a_shell_created_sentinel_stops_send(srv_with_halt):
    """S4: the sentinel file exists to work when the bridge does not. Nothing
    told this bridge anything -- no frame, no halt() call -- and the next send
    must still be refused."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        _configured(s, c)
        assert s.state == "configured"

        oh.sentinel_path.write_text("socket was dead, stopped by hand\n")

        with pytest.raises(server.BridgeError) as exc:
            s.send({"target_host": "app.example.test"}, REQ, timeout=0.5)
        assert exc.value.error_class == "halted", (
            "a sentinel file is a halt even when no frame ever said so; this "
            f"send was refused as {exc.value.error_class!r} instead"
        )
        c.settimeout(0.5)
        with pytest.raises(TimeoutError):
            c.recv(4096)
    finally:
        c.close()


def _send_and_answer(s, c, reader, answer: dict, **kwargs):
    """One send, answered with `answer`. Returns (outcome dict, sent header).

    The outcome carries `err` for a BridgeError and `reply` for a result, so a
    caller can assert on either without the send having to raise to be read.
    """
    out = {}

    def go():
        try:
            out["reply"] = s.send({"target_host": "app.example.test"},
                                  REQ, **kwargs)
        except server.BridgeError as exc:
            out["err"] = exc

    t = threading.Thread(target=go)
    t.start()
    try:
        header, _ = reader.read()
    except TimeoutError:
        # Not a bare TimeoutError out of the codec. A send that never framed
        # is the interesting failure here -- it means THIS side answered it --
        # and the answer it gave is the diagnosis, so say it.
        t.join(timeout=5)
        raise AssertionError(
            "no frame reached the wire; the send was answered before it, by "
            f"this side: {out.get('err') or out.get('reply')!r}") from None
    c.sendall(codec.encode({**answer, "id": header["id"]}))
    t.join(timeout=5)
    assert not t.is_alive(), "the send never returned"
    return out, header


def test_enforce_locally_false_reaches_the_wire_and_answers_the_same_way(srv_with_halt):
    """The seam the integration rig sends through, and the copy it replaced.

    This side refuses a send whenever the durable halt is armed, and that is
    right in production. It is fatal to a test OF THE EXTENSION: the frame
    never leaves, the assertion is satisfied by this dict of state, and it
    goes on passing with the extension wide open. `enforce_locally=False`
    drops exactly those refusals -- both halves are asserted below, zero
    frames against one -- and is the reason the rig can prove anything about
    a JVM's kill switch at all.

    THE COMPARISON AT THE END IS THE POINT. The rig used to reach past send()
    into `_request` and translate the peer's `error` frame itself: a second
    copy of the five lines at the bottom of send(), which nothing compared
    with the original. A new frame type, a renamed `retry_after_us`, a changed
    message shape -- any of them would have been handled on one path and not
    the other, silently, with every test that goes through the unguarded path
    still asserting the old shape. There is one translation now, and this is
    what says both callers get it.
    """
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        reader = _configured(s, c)
        answer = {"v": 1, "t": "error", "class": "rate_limited",
                  "detail": "3 rps, 617000us to the next slot",
                  "retry_after_us": 617_000}

        guarded, _ = _send_and_answer(s, c, reader, answer)
        assert guarded["err"].error_class == "rate_limited"

        # Arm the durable halt by hand, exactly as S4's "the socket is dead,
        # stop from a shell" path does.
        oh.sentinel_path.write_text("stopped by hand\n")

        # Guarded: refused HERE, and ZERO frames on the wire. That absence is
        # what makes the guarded path useless for asking the extension
        # anything -- and it is asserted rather than described, because the
        # whole justification for the keyword rests on it.
        with pytest.raises(server.BridgeError) as local:
            s.send({"target_host": "app.example.test"}, REQ, timeout=0.5)
        assert local.value.error_class == "halted"
        c.settimeout(0.5)
        with pytest.raises(TimeoutError):
            c.recv(4096)
        c.settimeout(5)

        # Unguarded, with that same sentinel still armed: the frame goes out.
        unguarded, header = _send_and_answer(s, c, reader, answer,
                                             enforce_locally=False)
        assert header["t"] == "send", header
        assert header["engagement_id"] == "e-1", (
            "the unguarded path must build the same frame, id and all -- it "
            "is the same method, not a second one")
        assert oh.halted is True, "the sentinel was cleared by a send"

        assert unguarded["err"].error_class == guarded["err"].error_class
        assert unguarded["err"].retry_after_us == guarded["err"].retry_after_us
        assert str(unguarded["err"]) == str(guarded["err"]) == \
            "rate_limited: 3 rps, 617000us to the next slot"
    finally:
        c.close()


def test_enforce_locally_false_still_refuses_the_keys_send_stamps(srv_with_halt):
    """The carve-out, pinned. `enforce_locally` drops the three DENIALS and
    nothing else: the reserved-key guard catches a malformed call -- a bug,
    not a denial -- and a caller who could turn a send into a halt frame by
    passing `guarded=False` would have found a way around the one guard that
    is not about policy at all."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        _configured(s, c)
        with pytest.raises(server.BridgeError, match="engagement_id"):
            s.send({"target_host": "app.example.test",
                    "engagement_id": "SOMEONE-ELSE"}, REQ,
                   enforce_locally=False)
        c.settimeout(0.5)
        with pytest.raises(TimeoutError):
            c.recv(4096)
    finally:
        c.close()


def test_halt_arms_the_durable_record_and_only_resume_clears_it(srv_with_halt):
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        reader = _configured(s, c)

        s.halt("operator pressed stop")
        header, _ = reader.read()
        assert header["t"] == "halt"
        assert oh.halted is True
        assert oh.sentinel_path.exists()
        assert halt_mod.OperatorHalt(oh.engagement_dir, conn).halted is True

        s.resume()
        header, _ = reader.read()
        assert header["t"] == "resume"
        assert oh.halted is False
        assert not oh.sentinel_path.exists()
        assert halt_mod.OperatorHalt(oh.engagement_dir, conn).halted is False
    finally:
        c.close()


def test_halt_arms_the_durable_record_before_the_frame_it_cannot_send(srv_with_halt):
    """halt() arms the durable record FIRST, and a dead socket proves it.

    S4 names the dead socket as the reason the sentinel exists at all, and a
    dead socket is the likeliest thing to be wrong at the moment someone hits
    stop. Arming after the send makes exactly that case the one path that
    loses the halt: the operator gets an exception and NOTHING anywhere is
    halted -- no frame, no sentinel, no row, and the next Burp start finds no
    standing halt to re-assert.

    The mirror ordering inside OperatorHalt.halt (sentinel before row) has
    test_the_sentinel_is_written_before_the_row behind it. This ordering, on
    the bridge, had nothing but a comment: reversing the two statements passed
    the entire suite except the plan's byte-compare, which a re-sync would
    have carried the reversal straight into.
    """
    s, oh, conn = srv_with_halt
    assert s._conn is None, "this test is only about the socket being dead"

    with pytest.raises(server.BridgeError, match="not connected") as exc:
        s.halt("operator pressed stop, socket already dead")
    assert exc.value.error_class == "bridge_lost"

    assert oh.halted is True, (
        "the operator pressed stop and was told it failed; if nothing is "
        "halted, the stop button did nothing at all"
    )
    assert oh.sentinel_path.exists(), (
        "the sentinel is the path that works when the bridge does not -- it "
        "is the one that must exist after a send that could not happen"
    )
    assert halt_mod.OperatorHalt(oh.engagement_dir, conn).halted is True, (
        "the next Burp start reads the store and the file, not this object"
    )
    assert conn.execute("SELECT COUNT(*) FROM agent_action WHERE tool=?",
                        (halt_mod.HALT_TOOL,)).fetchone()[0] == 1, (
        "the audit trail must say who stopped the run even when the frame "
        "never reached anyone"
    )
    assert s.state == "waiting", (
        "the bridge state is the connection's, and there is no connection; "
        "the halt that outlives it is the one in OperatorHalt"
    )


def test_resume_leaves_the_durable_halt_armed_when_the_frame_cannot_be_sent(srv_with_halt):
    """resume() disarms LAST, and the same dead socket proves it.

    A resume the peer never received must not lift a standing halt. Reversed,
    the operator is told the resume failed while issuance has been silently
    re-armed for the next Burp start -- a lifted halt nobody asked for,
    reported as a failure. S4's direction is the other one: unknown state is
    stop, so every failure before the frame reaches the wire leaves the halt
    standing.
    """
    s, oh, conn = srv_with_halt
    oh.halt("operator pressed stop")
    assert s._conn is None, "this test is only about the socket being dead"

    with pytest.raises(server.BridgeError, match="not connected"):
        s.resume()

    assert oh.halted is True, (
        "a resume nobody received lifted the halt anyway"
    )
    assert oh.sentinel_path.exists()
    assert halt_mod.OperatorHalt(oh.engagement_dir, conn).halted is True, (
        "and the next Burp start would have come up armed"
    )
    assert conn.execute("SELECT COUNT(*) FROM agent_action WHERE tool=?",
                        (halt_mod.RESUME_TOOL,)).fetchone()[0] == 0, (
        "nothing was resumed, so nothing should say it was"
    )


def test_a_reassert_that_cannot_be_sent_closes_the_connection(srv_with_halt):
    """`_reassert_halt` returns False and the caller drops the connection.

    Nothing else in this file exercises that arm: the send it guards only
    fails when the socket dies inside the hello handler, so the failure is
    injected rather than raced for. Carrying on would leave a peer that never
    received the halt believing it may issue -- and this side, having set
    state='halted', would show an operator a stop that is not in force
    anywhere.
    """
    s, oh, conn = srv_with_halt
    oh.halt("client called: stop everything")

    real_send = s._send

    def refuse(header, body=b""):
        if header.get("t") == "halt":
            raise server.BridgeError("send failed: [Errno 32] Broken pipe",
                                     error_class="bridge_lost")
        return real_send(header, body)

    s._send = refuse

    c = _client(s.socket_path)
    try:
        _hello(c)
        # _serve's finally runs _reset(), which is the observable consequence.
        _await(lambda: s.state == "waiting",
               f"the connection was kept after a failed re-assert: {s.state!r}")
        c.settimeout(0.5)
        assert c.recv(4096) == b"", "the peer socket was left open"
    finally:
        c.close()


def test_send_refuses_a_reply_that_is_not_a_result_or_an_error(srv_with_halt):
    """_deliver routes `configured` by correlation id like anything else, so a
    peer that answers a send with one gets that frame handed straight back.
    Returning it as a result would put `status=None` into an evidence row and
    call it an exchange that happened."""
    s, oh, conn = srv_with_halt
    c = _client(s.socket_path)
    try:
        reader = _configured(s, c)
        out = {}

        def go():
            try:
                s.send({"target_host": "app.example.test"}, REQ)
            except server.BridgeError as exc:
                out["err"] = exc

        t = threading.Thread(target=go)
        t.start()
        header, _ = reader.read()
        c.sendall(codec.encode({"v": 1, "t": "configured", "id": header["id"],
                                "config_epoch": 2}))
        t.join(timeout=5)
        assert not t.is_alive()
        assert "configured" in str(out["err"])
        assert out["err"].error_class is None
    finally:
        c.close()


# ---- Plan 4's unsolicited proxy traffic ---------------------------------
#
# `exchange`, `denial` and `dropped` frames answer no request: nothing is
# waiting on an id, so `_deliver` would drop them on the floor. They go to
# `on_exchange`, on the READ THREAD, with the same discipline `on_hello` and
# `on_halted` carry -- and with one deliberate difference, which the first two
# tests below are about.


def _exchange_server(tmp_path, halt, sink):
    s = server.BridgeServer(tmp_path / "x.sock", engagement_id="e-1",
                            operator_halt=halt, on_exchange=sink)
    s.start()
    return s


def _push(c, frame: bytes, srv, predicate, timeout=5.0):
    """Write an unsolicited frame and wait for the read thread to act on it."""
    c.sendall(frame)
    deadline = time.time() + timeout
    while time.time() < deadline and not predicate():
        time.sleep(0.005)
    return predicate()


def test_an_exchange_frame_reaches_the_sink_with_both_halves(tmp_path, halt):
    seen = []
    s = _exchange_server(tmp_path, halt,
                         lambda h, req, resp: seen.append((h, req, resp)))
    try:
        c = _connected(s)
        frame = codec.encode_two(
            {"v": 1, "t": "exchange", "via": "proxy", "source": "operator",
             "method": "GET", "url": "http://app.test/x", "status": 200,
             "ms": 12, "outcome": "ok"},
            b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\nhi")
        assert _push(c, frame, s, lambda: len(seen) == 1)
        header, request, response = seen[0]
        assert header["url"] == "http://app.test/x"
        # The two halves arrive APART. Spliced, the far side would hash one
        # blob for what S5 stores as two, and every request digest in the
        # engagement would carry its response's bytes.
        assert request == b"GET / HTTP/1.1\r\n\r\n"
        assert response == b"HTTP/1.1 200 OK\r\n\r\nhi"
        c.close()
    finally:
        s.stop()


def test_a_dropped_frame_reaches_the_sink_and_does_not_close_the_channel(tmp_path, halt):
    """Before this arm existed a `dropped` frame fell through `_handle` to
    `return False`: the drop report -- the one thing that says a run's coverage
    is a floor -- closed the connection that carried it, and DENY-ALL is where
    a closed connection lands."""
    seen = []
    s = _exchange_server(tmp_path, halt,
                         lambda h, req, resp: seen.append(h))
    try:
        c = _connected(s)
        assert _push(c, codec.encode({"v": 1, "t": "dropped", "n": 7,
                                      "source": "crawler"}),
                     s, lambda: len(seen) == 1)
        assert seen[0]["n"] == 7
        assert seen[0]["source"] == "crawler"
        # Still live: another frame gets through on the same connection.
        assert _push(c, codec.encode({"v": 1, "t": "denial", "via": "proxy",
                                      "url": "http://app.test/y",
                                      "error_class": "scope_denied"}),
                     s, lambda: len(seen) == 2)
        assert s.state == "connected"
        c.close()
    finally:
        s.stop()


def test_a_sink_that_throws_does_not_take_the_connection_down(tmp_path, halt):
    """The one callback whose throw is NOT fatal, and S4 is why: a wedged
    harness or a lost record changes what hx KNOWS, never what it ALLOWS. A
    bookkeeping bug closing the channel would drop the extension to DENY-ALL
    and stop the operator's browsing -- the failure turned into an outage.

    `on_halted` is the opposite case and stays that way: a stop nothing wrote
    down is a stop that did not happen.
    """
    calls = []

    def sink(header, request, response):
        calls.append(header)
        raise RuntimeError("the store is on fire")

    s = _exchange_server(tmp_path, halt, sink)
    try:
        c = _connected(s)
        frame = codec.encode_two({"v": 1, "t": "exchange",
                                  "url": "http://app.test/x"}, b"a", b"b")
        # TWO calls for one frame: the exchange, and the `dropped` frame that
        # says the exchange was lost. The retry is attempted ONCE and only for
        # a frame that was not itself a drop report, so a sink that raises on
        # everything costs one extra call and not a recursion.
        assert _push(c, frame, s, lambda: len(calls) == 2)
        assert calls[0]["t"] == "exchange"
        assert calls[1] == {"v": 1, "t": "dropped", "n": 1}
        assert isinstance(s.exchange_callback_error, RuntimeError)
        assert s.exchange_errors == 2      # the exchange, and the retry
        # ...and the NEXT one still arrives, which is what "not fatal" means.
        assert _push(c, frame, s, lambda: len(calls) == 4)
        assert s.state == "connected"
        c.close()
    finally:
        s.stop()


def test_a_lost_exchange_is_handed_back_as_a_drop(tmp_path, halt):
    """The coverage floor, on this side of the bridge.

    `exchange_callback_error` and `exchange_errors` are kept, and nothing
    outside tests/ reads either -- so a run whose every exchange frame was
    malformed reported COMPLETE coverage. That is the Java side's "a Burp log
    line is not the coverage floor" wearing a different hat. `run.dropped_total`
    is the number S5 makes the floor, and the only way a loss here reaches it
    is a `dropped` frame.
    """
    seen = []

    def sink(header, request, response):
        seen.append(header)
        if header.get("t") != "dropped":
            raise RuntimeError("the store is on fire")

    s = _exchange_server(tmp_path, halt, sink)
    try:
        c = _connected(s)
        frame = codec.encode_two({"v": 1, "t": "exchange", "via": "proxy",
                                  "source": "crawler",
                                  "url": "http://app.test/x"}, b"a", b"b")
        assert _push(c, frame, s, lambda: len(seen) == 2)
        assert seen[1]["t"] == "dropped" and seen[1]["n"] == 1
        # Against the CRAWLER's run, not the operator's. `hx.capture._run`
        # turns this string into a run KIND, and filing the crawler's lost
        # exchange against the operator inflates the wrong row's floor.
        assert seen[1]["source"] == "crawler"
        assert s.exchange_errors == 1      # the retry succeeded
        assert s.state == "connected"
        c.close()
    finally:
        s.stop()


def test_a_lost_drop_report_is_not_re_reported_as_another_drop(tmp_path, halt):
    """One extra call, never a recursion -- and never a count of its own.

    A `dropped` frame the sink could not record is already the coverage floor
    failing to land; answering it with a second `dropped` frame would be a
    number this side invented, and a sink that refuses every drop report would
    invent one per frame forever.
    """
    seen = []

    def sink(header, request, response):
        seen.append(header)
        raise RuntimeError("the store is on fire")

    s = _exchange_server(tmp_path, halt, sink)
    try:
        c = _connected(s)
        assert _push(c, codec.encode({"v": 1, "t": "dropped", "n": 5}),
                     s, lambda: s.exchange_errors == 1)
        time.sleep(0.05)
        assert len(seen) == 1 and seen[0]["n"] == 5
        assert s.exchange_errors == 1
        assert s.state == "connected"
        c.close()
    finally:
        s.stop()


def test_a_malformed_two_body_payload_is_counted_not_raised(tmp_path, halt):
    """`_serve` closes the connection on a FrameError, so a split that raised
    out of `_handle` would be the same outage by another route."""
    seen = []
    s = _exchange_server(tmp_path, halt, lambda h, q, r: seen.append(h))
    try:
        c = _connected(s)
        # Declares two bodies; the payload holds one truncated length prefix.
        bad = codec.encode({"v": 1, "t": "exchange", "url": "http://app.test/x",
                            codec.BODIES_KEY: 2}, b"\x00\x00")
        assert _push(c, bad, s, lambda: s.exchange_errors == 1)
        assert isinstance(s.exchange_callback_error, codec.FrameError)
        # The frame never became an exchange row -- and it did not vanish
        # either. A payload that could not be split is a record hx does not
        # have, so it reaches the sink as a drop instead.
        assert seen == [{"v": 1, "t": "dropped", "n": 1}]
        good = codec.encode_two({"v": 1, "t": "exchange",
                                 "url": "http://app.test/y"}, b"a", b"b")
        assert _push(c, good, s, lambda: len(seen) == 2)
        assert s.state == "connected"
        c.close()
    finally:
        s.stop()


def test_an_exchange_frame_with_no_sink_installed_keeps_the_channel(tmp_path, halt):
    """A harness that has not wired capture up yet is a harness that loses the
    records, not one that loses the connection."""
    s = server.BridgeServer(tmp_path / "n.sock", engagement_id="e-1",
                            operator_halt=halt)
    s.start()
    try:
        c = _connected(s)
        frame = codec.encode_two({"v": 1, "t": "exchange",
                                  "url": "http://app.test/x"}, b"a", b"b")
        c.sendall(frame)
        c.sendall(codec.encode({"v": 1, "t": "dropped", "n": 1}))
        # Nothing to observe on the sink, so observe the channel instead: a
        # hello over the same connection still lands.
        assert _push(c, codec.encode({"v": 1, "t": "halted", "reason": "x",
                                      "host": "h", "window": "w"}),
                     s, lambda: s.last_halted is not None)
        c.close()
    finally:
        s.stop()


def _reject_next_peer(monkeypatch):
    """Make SO_PEERCRED report a foreign uid, the way
    `test_so_peercred_rejects_a_foreign_uid` does. A test cannot connect as
    another account, and the branch worth covering is the one that only
    another account can reach."""
    real_getsockopt = socket.socket.getsockopt

    def fake_getsockopt(self, level, optname, buflen=0):
        if optname == socket.SO_PEERCRED:
            return struct.pack("3i", 4242, os.getuid() + 1, os.getgid())
        return real_getsockopt(self, level, optname, buflen)

    monkeypatch.setattr(socket.socket, "getsockopt", fake_getsockopt)


def test_a_refused_peer_is_counted_and_logged_rather_than_dropped_in_silence(
        srv, monkeypatch, caplog):
    """S6's uid check left NO TRACE, and it is the one connection event on
    this socket that is a security event rather than a misconfiguration.

    `rejected_hellos` sits four lines of code away and has been counted since
    Plan 2 -- a wrong engagement_id, which is an operator pointing a harness
    at the wrong store. Another UID on this machine reaching for a capability
    that can send arbitrary HTTP into a client's production estate got a bare
    `return`: no counter, no log line, no row. An attempt nobody can see is
    indistinguishable from no attempt.

    Both halves are asserted. The counter is what a caller can read; the log
    line is what an operator sees at the time, and `hx` installs no handler,
    so the LEVEL is load-bearing -- under Python's default configuration a
    WARNING reaches lastResort on stderr and an INFO does not.
    """
    _reject_next_peer(monkeypatch)
    before = srv.rejected_peers
    with caplog.at_level(logging.WARNING, logger="hx.bridge.server"):
        c = _client(srv.socket_path)
        try:
            hello = codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                                  "pid": os.getpid(), "burp_version": "x",
                                  "instance_id": "i-1", "engagement_id": "e-1"})
            assert _never_served(c, hello) == b""
            _await(lambda: srv.rejected_peers > before,
                   "a peer was refused by SO_PEERCRED and nothing counted it")
        finally:
            c.close()

    assert srv.rejected_peers == before + 1
    assert srv.last_rejected_peer["uid"] == os.getuid() + 1
    assert srv.last_rejected_peer["pid"] == 4242
    assert "exe" in srv.last_rejected_peer

    warnings_ = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings_, (
        "the refusal was counted and not logged. The counter is read by "
        "whoever thinks to look; the log line is what reaches an operator who "
        "does not know to")
    text = warnings_[-1].getMessage()
    assert str(os.getuid() + 1) in text and "4242" in text, text


def test_a_refused_peer_is_still_refused_and_none_of_this_serves_it(
        srv, monkeypatch):
    """The counter must not be the only thing that changed. A diagnostic that
    also opened the door would be worse than no diagnostic, and the two
    fields the uid check `return`s in front of are what say the connection was
    REFUSED rather than merely quiet."""
    _reject_next_peer(monkeypatch)
    c = _client(srv.socket_path)
    try:
        assert _never_served(c, codec.encode(
            {"v": 1, "t": "hello", "ext_version": "0.1", "pid": os.getpid(),
             "burp_version": "x", "instance_id": "i-1",
             "engagement_id": "e-1"})) == b""
        _await(lambda: srv.rejected_peers == 1, "the refusal was not counted")
        assert (srv.peer_uid, srv.peer_pid, srv.peer_exe) == (None, None, None)
        assert srv.state == "waiting"
        assert srv.hello is None
    finally:
        c.close()


def test_the_accepted_peers_executable_is_resolved_and_recorded(srv):
    """S6: "peer credentials are checked and the connecting pid's executable
    is logged." Nothing resolved it, on either path. This is a real pid -- the
    test's own -- so the readlink succeeds and the value is the interpreter
    running this suite, which is what makes the assertion a real one rather
    than a check that some string was stored."""
    c = _connected(srv)
    try:
        assert srv.peer_pid == os.getpid()
        assert srv.peer_exe == os.readlink(f"/proc/{os.getpid()}/exe")
    finally:
        c.close()


def test_an_unresolvable_executable_says_which_kind_of_unresolvable(monkeypatch):
    """`peer_exe` NEVER RAISES and never answers "unknown".

    It runs inside `_serve` on the accept-loop thread, where a throw takes the
    connection down -- and a diagnostic that can refuse a peer is not a
    diagnostic. The three answers are also deliberately different strings: for
    a peer running as ANOTHER uid, which is exactly the peer this exists to
    describe, `/proc/<pid>/exe` needs PTRACE_MODE_READ and the kernel refuses
    it unless hx is root. "unknown" would read as "no executable" rather than
    "not permitted to look", and the difference is the whole diagnostic.
    """
    def raiser(exc):
        def go(_path):
            raise exc
        return go

    monkeypatch.setattr(server.os, "readlink", raiser(PermissionError(13, "x")))
    assert "permission denied" in server.peer_exe(1).lower()
    monkeypatch.setattr(server.os, "readlink", raiser(FileNotFoundError(2, "x")))
    assert "gone" in server.peer_exe(1)
    monkeypatch.setattr(server.os, "readlink", raiser(OSError(5, "EIO")))
    assert server.peer_exe(1).startswith("<unreadable:")
    # A pid this process cannot possibly be resolving, through the REAL
    # readlink: the answer is still a string and still not an exception.
    monkeypatch.undo()
    assert isinstance(server.peer_exe(0x7FFFFFFF), str)
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

import logging
import os
import secrets
import socket
import struct
import threading
import time
from pathlib import Path

from hx.bridge import codec

# The first logger in `src/`, and it is deliberately a plain module logger with
# no handler and no configuration: a library that installs a handler decides
# for its embedder where the operator's diagnostics go. `hx` has no logging
# setup yet, so under Python's default these records reach lastResort at
# WARNING -- which is the level the refusal below uses, and is why the refusal
# is visible on a bare `python -c` while the accept is not.
_log = logging.getLogger(__name__)


def peer_exe(pid: int) -> str:
    """What `/proc/<pid>/exe` points at, or why it could not be read. S6.

    A DIAGNOSTIC, NEVER A CHECK, and the distinction is the whole reason this
    is a separate function with a docstring rather than an inline readlink.
    Between the `getsockopt` that produced this pid and this call, the peer
    can have exited and the pid can have been reused -- so the answer names a
    process that may not be the one that connected. S6 says the executable is
    LOGGED and says the credentials are CHECKED, and those are two different
    sentences about two different facts: the uid is what authorises, and this
    is what a human reads afterwards.
    """
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except PermissionError:
        # THE COMMON CASE FOR THE PATH THAT MATTERS, and it is stated rather
        # than pretended around. Reading this link needs PTRACE_MODE_READ, so
        # for a peer running as ANOTHER uid -- exactly the peer this is most
        # worth knowing about -- the kernel refuses it unless hx is root. The
        # uid, the pid and the refusal itself are still recorded; the program
        # name is the part that is not available, and saying "unknown" would
        # read as "no executable" rather than "not permitted to look".
        return "<unreadable: permission denied (needs PTRACE_MODE_READ)>"
    except FileNotFoundError:
        return "<gone: the process exited before it could be resolved>"
    except OSError as exc:
        # Never raises. This runs inside `_serve`, on the accept-loop thread,
        # where a throw would take the connection down -- and a diagnostic
        # that can refuse a peer is not a diagnostic.
        return f"<unreadable: {exc}>"


class BridgeError(Exception):
    """The bridge cannot start, or was asked to do something out of order.

    `error_class` is the send path's vocabulary (spec S6): the class the peer
    put on an `error` frame, or the class this side refused under before the
    frame ever reached the wire. It is None when the failure is not a send-path
    failure at all -- a malformed call, a configure the peer refused -- so a
    caller mapping classes onto `denial` rows through `records.DENIAL_KIND`
    must check for None rather than index blindly.

    `retry_after_us` is set only for `rate_limited`, the one class that carries
    a retry hint. NOTHING IN THIS FILE RETRIES: S6 is explicit that a replayed
    state-changing request is worse than a failed one, so retry is a decision
    the caller makes explicitly, and records.
    """

    def __init__(self, message: str, *, error_class: str | None = None,
                 retry_after_us: int | None = None):
        super().__init__(message)
        self.error_class = error_class
        self.retry_after_us = retry_after_us


def socket_path_for(engagement_id: str) -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return Path(runtime) / "hx" / f"{engagement_id}-{secrets.token_hex(4)}.sock"


class BridgeServer:
    # Error classes under which BridgeClient.handle() actually drops to
    # DENY-ALL: `bad_config` calls denyAll() before answering, and
    # `protocol_mismatch` returns false out of handle(), which trips
    # readLoop()'s finally block. `engagement_mismatch` and `bad_frame`
    # answer error and carry on configured -- resetting THIS side for those
    # would make it report state="connected", config_epoch=0 while the
    # extension is still configured and live, the reverse of the bug this
    # reset exists to fix, and the more dangerous direction: the operator's
    # console says nothing may be sent while it can. See the `case` arms in
    # extension/src/hx/bridge/BridgeClient.java's handle() for the exact
    # strings.
    _DENYING_CONFIGURE_ERRORS = frozenset({"bad_config", "protocol_mismatch"})

    # The key a delivered frame's body arrives under. It mirrors
    # BridgeClient.BODY_KEY on the Java side, and codec._check_header refuses a
    # bytes value, so a reply dict that ever got re-encoded as a frame with the
    # body still attached fails loudly instead of putting evidence in a header.
    BODY_KEY = "@body"

    # Keys send() stamps itself. `**req` is spliced OVER the frame send()
    # builds, so a caller's key wins: `t` alone would turn a send into a halt
    # frame nobody correlates, `engagement_id` would address whichever
    # extension answered, and `id` would collide with a live correlation id.
    # They are refused rather than silently overwritten, which would leave the
    # caller believing something else happened.
    _RESERVED_SEND_KEYS = frozenset({"v", "t", "id", "deadline_us",
                                     "engagement_id"})

    def __init__(self, socket_path: Path, engagement_id: str, operator_halt,
                 on_hello=None, on_halted=None, on_exchange=None):
        """
        `operator_halt` is an `hx.halt.OperatorHalt` -- duck-typed, so this
        module keeps no dependency on the store, and tests can attach anything
        with `.halted`, `.reason`, `.halt()` and `.resume()`. `.halted` and
        `.reason` are read on the read thread, which is why OperatorHalt
        answers them from memory and a stat() rather than from the database.

        IT IS REQUIRED, and the Java side made the same call for the same
        field: HxExtension.initialize() refuses to come up without
        `-Dhx.halt_sentinel` because "an extension that went live without one
        would have two of the three paths spec s4 promises, silently". The
        same is true here. Optional, it made the whole durable halt opt-in: a
        HALTED file placed by hand -- S4's named "the socket is dead, stop by
        hand" path -- did not stop send(), and halt() wrote neither sentinel
        nor audit row. Measured with the argument omitted:

            sentinel on disk: True   operator_halt attr: None
            SEND REACHED THE WIRE with a HALTED sentinel present
            after server.halt(): agent_action rows = 0

        The extension still refused via its own poller, so S4's enforcement
        invariant held; what was lost was durability and the harness-side
        refusal. S4 promises three paths, and an opt-in third path is not a
        promise. A caller with no engagement -- a test harness -- supplies a
        sentinel in a directory of its own, which is exactly the discipline
        the Java side imposes on itself.

        `on_hello`, `on_halted` and `on_exchange` are ALL called ON THE READ
        THREAD, so none may touch a sqlite3 connection opened elsewhere: it
        belongs to the thread that created it and raises ProgrammingError
        anywhere else (tests/test_halt.py demonstrates it). Hand the work to
        the thread that owns the store instead.

        `on_exchange(header, request, response)` takes Plan 4's proxy traffic:
        `exchange`, `denial` and `dropped` frames, which are UNSOLICITED --
        nothing is waiting on an id, so without a sink installed they are read
        and discarded. `hx.capture.Capture.on_exchange` has this shape.

        IT IS THE ONE CALLBACK WHOSE THROW IS NOT FATAL. `on_halted` returning
        an exception closes the connection, because a stop nothing wrote down
        is a stop that did not happen. Capture is the opposite case and S4 says
        so: a wedged harness or a lost record changes what hx KNOWS, never what
        it ALLOWS, so a bookkeeping failure here must not become an outage on
        the operator's browser. The exception is kept in
        `exchange_callback_error`, the channel is kept with it, and the lost
        record is handed back as a `dropped` frame so the run's coverage floor
        moves -- see `_capture`, which explains why keeping it was not enough.
        """
        if operator_halt is None:
            # The signature already refuses an OMITTED argument. This refuses
            # an explicit None, which is the same fail-open with a keystroke
            # in front of it, and refuses it at construction rather than at
            # the first send -- the Java side's `extension idle` shape.
            raise BridgeError(
                "operator_halt is required and may not be None. It is S4's "
                "third kill path: the sentinel file that works when the "
                "bridge does not. A caller with no engagement supplies an "
                "hx.halt.OperatorHalt over a directory of its own, the same "
                "way HxExtension refuses to initialise without "
                "-Dhx.halt_sentinel."
            )
        self.socket_path = Path(socket_path)
        self.engagement_id = engagement_id
        self.on_hello = on_hello
        self.on_halted = on_halted
        self.on_exchange = on_exchange
        self.operator_halt = operator_halt
        # The last unsolicited `halted` frame, kept so a harness with no
        # on_halted callback installed can still see why issuance stopped.
        self.last_halted: dict | None = None
        self.halted_callback_error: BaseException | None = None
        # The last thing an `on_exchange` frame failed on -- a malformed
        # two-body payload, or a throw out of the sink. Recorded rather than
        # raised: see the note on the constructor's `on_exchange`. These two
        # are DIAGNOSTICS, read by tests and by whoever is debugging the
        # bridge; the coverage consequence of the same failure travels the
        # `dropped` frame `_capture` hands back, because nothing outside
        # tests/ reads either of these and a run cannot get its floor from a
        # number no one looks at.
        #
        # `exchange_errors` COUNTS FAILED SINK CALLS, NOT RECORDS LOST, and the
        # two stopped being the same number when `_count_as_dropped` arrived:
        # ONE lost record whose `dropped` retry also raises counts TWO, the
        # original call and the retry. That is the right number for a
        # diagnostic -- it is how many times the sink misbehaved, which is what
        # someone debugging the sink wants -- and the wrong one for coverage,
        # which is exactly why coverage does not come from here.
        # `run.dropped_total`, fed by the `dropped` frame, is the count of
        # RECORDS.
        self.exchange_callback_error: BaseException | None = None
        self.exchange_errors = 0

        self.state = "waiting"
        self.config_epoch = 0
        self.peer_uid: int | None = None
        self.peer_pid: int | None = None
        self.peer_exe: str | None = None
        self.hello: dict | None = None
        self.rejected_hellos = 0
        # Peers refused by SO_PEERCRED, i.e. another UID on this machine
        # reaching for this socket. It sits beside `rejected_hellos`
        # deliberately: the two are the same kind of number and one of them
        # existed while the other -- the one that is a security event rather
        # than a misconfiguration -- did not.
        self.rejected_peers = 0
        # The last one, for whoever is looking. Kept rather than only logged,
        # because `hx` installs no logging handler and a library that did
        # would be deciding for its embedder where diagnostics go.
        self.last_rejected_peer: dict | None = None

        self._srv: socket.socket | None = None
        self._conn: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._pending: dict[int, threading.Event] = {}
        self._replies: dict[int, dict] = {}
        self._next_id = 0
        self._generation = 0     # bumped per accepted connection; see _reset
        self._lock = threading.Lock()
        # A SEPARATE mutex from self._lock, deliberately. Reusing the state
        # mutex would hold it across a blocking sendall() and stall the
        # _deliver() that wakes the _request() waiting on the very frame being
        # written.
        self._send_lock = threading.Lock()

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
        if self._conn is not None:
            try:
                # shutdown(), not just close(): the accept-loop thread may be
                # blocked in conn.recv() with no timeout set on that socket.
                # A bare close() from this thread does not reliably unblock a
                # concurrent recv() on the same fd on Linux -- verified by
                # reproduction, stop() hung for the full join timeout with the
                # accept thread left permanently blocked. shutdown(SHUT_RDWR)
                # forces that pending recv() to return 0 immediately.
                self._conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
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
                # looks alive and silently never accepts again, so no
                # exception may escape here.
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
                #
                # COUNTED AND LOGGED, and it used to be a bare `return`. This
                # is the one security-relevant connection event on this socket
                # -- another account on this machine reaching for a capability
                # that can send arbitrary HTTP into a client's production
                # estate -- and it left no counter, no log line and no row, in
                # contrast with `rejected_hellos` four lines of code away. An
                # attempt nobody can see is indistinguishable from no attempt,
                # and the refusal is exactly the thing worth knowing happened.
                self.rejected_peers += 1
                self.last_rejected_peer = {"pid": pid, "uid": uid,
                                           "exe": peer_exe(pid)}
                _log.warning(
                    "hx bridge: refused a peer on %s -- uid %d is not %d "
                    "(pid %d, exe %s). The socket authenticates a UID; a "
                    "different one has no business here at all.",
                    self.socket_path, uid, os.getuid(), pid, peer_exe(pid))
                return
            self.peer_pid, self.peer_uid = pid, uid
            # S6: "peer credentials are checked and the connecting pid's
            # executable is LOGGED". Nothing resolved it, so the second half
            # of that sentence was unmet on the path that succeeds as well as
            # on the one that refuses. It is a diagnostic and never a check --
            # see `peer_exe` for why it cannot be one.
            self.peer_exe = peer_exe(pid)
            _log.info("hx bridge: peer accepted on %s -- uid %d, pid %d, "
                      "exe %s", self.socket_path, uid, pid, self.peer_exe)

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
            # A durable halt is re-asserted HERE, before on_hello runs and so
            # before any configure: on_hello is where a harness pushes scope,
            # and configure() cannot be called before a hello at all. That
            # ordering IS the guarantee -- a peer that learned its scope first
            # would be armed for the length of a round trip.
            if not self._reassert_halt():
                return False
            if self.on_hello:
                self.on_hello(header)
            return True

        if t == "halted":
            # Unsolicited, no id: auto-halt is extension-initiated, so there is
            # no outstanding request to answer. Without this frame an auto-halt
            # is invisible until the next send fails, and `run.status =
            # aborted` has no stop_reason to record. The frame is
            # {reason, host, window}.
            self.last_halted = header
            with self._lock:
                self.state = "halted"
            if self.on_halted:
                try:
                    self.on_halted(header)
                except Exception as exc:
                    # The callback is what makes this durable -- it is where
                    # the run is marked aborted and, if the harness wants the
                    # stop to survive a Burp restart, where OperatorHalt.halt
                    # is called. A callback that threw recorded nothing, so
                    # drop to DENY-ALL rather than carry on beside a peer whose
                    # stop nothing has written down.
                    self.halted_callback_error = exc
                    return False
            return True

        if t in ("exchange", "denial", "dropped"):
            # `exchange` USED TO BE IN THE `_deliver` TUPLE BELOW and is not any
            # more, which is deliberate rather than an oversight. `_deliver`
            # answers a WAITER by `id`; these three are UNSOLICITED -- nothing
            # holds an id for them -- so `_deliver` had nothing to wake and the
            # frame reached no one. Nothing regressed on the send path when it
            # moved: no solicited `exchange` reply exists in either
            # implementation, and no `_request` waits on one.
            self._capture(t, header, body)
            return True

        if t == "configured":
            self._deliver(header, body)
            return True

        if t in ("result", "error", "identity_registered"):
            self._deliver(header, body)
            return True

        return False

    def _capture(self, t: str, header: dict, body: bytes) -> None:
        """Plan 4's unsolicited proxy traffic, handed to the sink.

        NOTHING RAISES OUT OF HERE. `_serve` closes the connection on a
        FrameError, and DENY-ALL is where a closed connection lands -- so a
        malformed body or a sink that threw would take the operator's browsing
        down with it, and the `halt` path with it. S4: a lost record changes
        what hx knows, never what it allows. `codec.decode` leaves the two-body
        split to `split_bodies` for exactly this reason; see the note there.

        THE FAILURE IS KEPT *AND* COUNTED WHERE COVERAGE IS READ. Keeping it in
        `exchange_callback_error` / `exchange_errors` was the whole of it, and
        nothing outside `tests/` ever read either -- so a run whose every
        exchange frame was malformed reported COMPLETE coverage, which is the
        Java side's "a Burp log line is not the coverage floor" wearing a
        different hat. A frame that could not be recorded is a record hx does
        not have, so it goes back to the sink as a one-record `dropped` frame:
        `run.dropped_total` is the number S5 makes the floor, and this is how a
        loss on THIS side reaches it.

        The retry is attempted ONCE and only for a frame that was not itself a
        drop report, so a sink that raises on everything costs one extra call
        and not a recursion; if that call fails too, the count stands and the
        channel is still kept.

        AND THAT LAST CASE LOSES THE COVERAGE FLOOR TOO -- named here because
        it is the same lesson one layer up, and MEASURED in Task 9 against a
        real Burp: with a sink that raises on every frame, three browsed
        requests produced `exchange_errors = 6` (three exchanges and their
        three `dropped` retries), no exchange rows, and `run.dropped_total`
        STILL 0. The three requests reached the target and were served, which
        is right -- S4 is unconditional -- but a reader of that run sees
        complete coverage over an hour in which nothing was recorded at all.
        `exchange_errors` is the only thing on this side that says otherwise
        and NOTHING OUTSIDE tests/ READS IT, which is precisely the criticism
        this method's own paragraph above makes of the version before it.
        The floor moves only for a sink that fails on exchanges and SUCCEEDS on
        `dropped` frames -- the saturated-queue case it was built for, where
        the far side is slow rather than broken.

        Not fixed here, and the reason is that there is nowhere honest to put
        it: `run.dropped_total` is a column in the store, the store is what the
        sink writes to, and a sink that cannot be written to cannot record that
        it could not be written to. It needs a channel that is not the sink --
        an operator-facing warning at `hx info`, or a harness-side log -- and
        that is a decision about the CLI, not about this method.

        Only `exchange` carries two bodies. `denial` and `dropped` describe
        something that produced no traffic, so they arrive with an empty body
        and are passed on as two empty halves -- which is what the far side's
        `Capture.on_exchange` reads for them anyway.
        """
        if self.on_exchange is None:
            return
        try:
            if t == "exchange":
                request, response = codec.split_bodies(header, body)
            else:
                request, response = b"", b""
            self.on_exchange(header, request, response)
        except Exception as exc:
            self.exchange_callback_error = exc
            self.exchange_errors += 1
            self._count_as_dropped(t, header)

    def _count_as_dropped(self, t: str, header: dict) -> None:
        """Tell the sink one record was lost. See `_capture`.

        The `source` is carried across so the loss lands on the run the frame
        belonged to; `hx.capture` reads an absent one as the operator's, which
        is the same answer it gives an omitted key on the wire.
        """
        if t == "dropped":
            return
        drop = {"v": codec.PROTOCOL_VERSION, "t": "dropped", "n": 1}
        if isinstance(header.get("source"), str):
            drop["source"] = header["source"]
        try:
            self.on_exchange(drop, b"", b"")
        except Exception as exc:
            self.exchange_callback_error = exc
            self.exchange_errors += 1

    def _reassert_halt(self) -> bool:
        """Tell a freshly connected peer it is still halted. False to close.

        Two findings from the Plan 2 review meet on this method: a second
        `hello` erased the halt (the epoch reset above is right -- a fresh
        hello IS a fresh session -- but the halt is not part of that session),
        and a halt did not survive a Burp restart, which is precisely when
        someone has already hit stop. `_reset()` cannot clear it either: the
        state lives in OperatorHalt, on disk, not in this object.
        """
        if not self.operator_halt.halted:
            return True
        reason = self.operator_halt.reason or "halted, no reason recorded"
        try:
            self._send({"v": codec.PROTOCOL_VERSION, "t": "halt",
                        "reason": reason})
        except BridgeError:
            # The connection is the thing that just failed, so it is the thing
            # to give up on: a peer that never received the halt must not be
            # left believing it may issue. Returning False closes it, and
            # _serve's finally puts this side back to DENY-ALL.
            return False
        with self._lock:
            self.state = "halted"
        return True

    def _deliver(self, header: dict, body: bytes = b"") -> None:
        rid = header.get("id")
        # A `result` frame's body is the redacted response bytes -- the
        # evidence the caller is about to hash into the blob store. Delivering
        # the header alone dropped it silently.
        header = {**header, self.BODY_KEY: body}
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
            raise BridgeError("not connected", error_class="bridge_lost")
        # Encoded OUTSIDE the mutex: it touches nothing shared, and holding a
        # send mutex across it would serialise work that needs no serialising.
        frame = codec.encode(header, body)
        try:
            # sendall() is not atomic -- it loops over send() and a large frame
            # parks mid-write once the socket buffer fills -- so two callers
            # inside it splice their frames together and the peer decodes
            # neither. Every write on this side is a control frame: halt,
            # resume, configure. The Java counterpart is a deliberate
            # `private synchronized void send` for exactly this reason.
            with self._send_lock:
                conn.sendall(frame)
        except OSError as exc:
            raise BridgeError(f"send failed: {exc}",
                              error_class="bridge_lost") from exc

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
            # S6 distinguishes timeout from bridge_lost and from
            # conn_refused, and the agent acts differently on each: this one
            # means the peer is alive and did not answer in time.
            raise BridgeError(f"no reply to {header['t']} within {timeout}s",
                              error_class="timeout")
        with self._lock:
            self._pending.pop(rid, None)
            # _reset() also sets every pending event, on disconnect, so that a
            # waiter does not outlive its connection -- that wakeup carries no
            # reply. Without this check, .pop(rid) raises a bare KeyError
            # instead of the documented BridgeError. Reproduced directly:
            # a peer that closes without ever replying woke this waiter via
            # _reset(), with no entry in _replies for it to collect.
            if rid not in self._replies:
                raise BridgeError(
                    f"peer disconnected before replying to {header['t']}",
                    # S6: every outstanding send fails with bridge_lost when
                    # the peer goes away, distinct from timeout, and NEVER
                    # auto-retried across the reconnect.
                    error_class="bridge_lost",
                )
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
        if reply.get("t") == "error":
            # The extension answers SOME refused configures by dropping to
            # DENY-ALL at epoch 0 -- including a refused RE-configure, which
            # discards the scope it was already holding -- but not all of
            # them. Only reset this side for the classes that actually deny;
            # see _DENYING_CONFIGURE_ERRORS. Resetting for the others would
            # make this side report state='connected', config_epoch=0 while
            # the extension is still configured and sending -- the opposite
            # disagreement from the one this reset was added to fix, and it
            # is this side that operators and Plan 5 read. Verified against a
            # live extension before the reset was added.
            #
            # Same gen/_conn guard as the success path: a newer connection's
            # state is not ours to clobber.
            if reply.get("class") in self._DENYING_CONFIGURE_ERRORS:
                with self._lock:
                    if gen == self._generation and self._conn is not None:
                        self.state = "connected"
                        self.config_epoch = 0
            # Surface what the peer actually said. Falling through to the
            # generic message below turns "engagement_mismatch: e-1 != e-2"
            # into "acknowledged configure without a config_epoch", which
            # sends the next debugger looking in the wrong place entirely.
            raise BridgeError(
                "peer refused configure: "
                f"{reply.get('class', 'unspecified')}: {reply.get('detail', '')}".rstrip(": ")
            )
        if "config_epoch" not in reply:
            raise BridgeError("peer acknowledged configure without a config_epoch")
        with self._lock:
            # Commit only if this is still the same connection. Without the
            # guard, a peer that acks and immediately disconnects leaves
            # state="configured" with no peer attached -- reproduced 59/60.
            # The generation check alone caught a NEW connection superseding
            # this one; it missed THIS connection resetting in the window
            # between _request() returning and this commit (reproduced 10/10
            # once that window was widened), because _reset() did not used to
            # advance the generation it guards on. The _conn check is belt
            # and braces: the generation check is the structural fix, this
            # makes the invariant obvious to the next reader.
            if gen != self._generation or self._conn is None:
                raise BridgeError("peer disconnected before configure completed")
            self.config_epoch = int(reply["config_epoch"])
            # A configure re-authorises SCOPE, not ISSUANCE. An operator who
            # halted because the scope went wrong, and is now pushing the
            # corrected scope, has not asked for issuance back -- only resume()
            # does that. Writing "configured" over "halted" here re-armed the
            # bridge with no `resume` on the wire and no log line, and the
            # extension's commit used to clear its own `halted` flag to match.
            # "halted" is still an accepted state on the way in (see the
            # precondition above): narrowing scope during an emergency stop is
            # exactly what an operator should be able to do.
            self.state = "halted" if self.state == "halted" else "configured"
        return self.config_epoch

    def register_identity(self, resolved, *, origins: tuple[str, ...]) -> None:
        """Register or refresh one identity in the extension.

        THE BODY IS NEVER LOGGED. Spec section 5 is explicit that `identity`
        is the one frame in this protocol whose payload is a live credential,
        and that neither side's diagnostics may print it. Everywhere else in
        this class logs freely -- `_serve` names the peer's uid, pid and exe
        at INFO, and a refused peer at WARNING -- because a frame *kind* and a
        correlation id are not secrets. This method's own log line below is
        held to the same rule the rest of the class already follows for
        everything it prints: it names `resolved.id` and `resolved.
        generation`, and nothing that touches `resolved.value` or
        `resolved.header`'s injected content ever reaches `_log`.

        `identity` is its own frame type rather than a `configure` key --
        `configure()` above refuses a later call naming a different rate or
        budget, because a run must not talk its way into a larger allowance
        mid-flight, and a programmatic refresh has to advance a generation
        WITHOUT re-opening scope. Folding identity into `configure` would
        either weaken that rule or make refresh impossible.

        The success and refusal frame types the peer answers with
        (`identity_registered`, or `error` carrying a `class` such as
        `stale_generation` for a generation that does not advance what the
        extension already holds) are this side's choice: the extension-side
        registry is a later task in this same plan and has not been built
        yet, so nothing upstream of this file pins them. `_handle` delivers
        both alongside `result`/`error` for exactly this method to collect.

        Raises BridgeError: whatever `_request` raises when the peer is gone
        or never answers, and `error_class` set to the peer's `class` on an
        `error` reply.
        """
        body = codec.identity_body(resolved.id, resolved.generation,
                                   resolved.header, resolved.value, origins)
        _log.debug("hx bridge: identity frame for %s generation %d -- kind "
                  "and generation only, never the injected value",
                  resolved.id, resolved.generation)
        reply = self._request({"v": codec.PROTOCOL_VERSION, "t": "identity",
                               "engagement_id": self.engagement_id}, body)
        t = reply.get("t")
        if t == "identity_registered":
            return
        if t == "error":
            raise BridgeError(
                "peer refused identity: "
                f"{reply.get('class', 'unspecified')}: "
                f"{reply.get('detail', '')}".rstrip(": "),
                error_class=reply.get("class"),
            )
        # ANYTHING ELSE IS A REFUSAL, and this method is the one that most
        # needs to say so. It used to test only for `error` and return on
        # everything else, so a reply of an unexpected shape read as "the
        # credential is now live in the extension" -- and every probe after it
        # would issue believing it carried a session it does not have, which
        # is the confusion this whole feature exists to remove. `send()` above
        # has always been strict about its reply type; this is the same rule.
        raise BridgeError(f"peer answered an identity frame with a {t!r} frame")

    def send(self, req: dict, body: bytes = b"", timeout: float = 30.0,
             *, enforce_locally: bool = True) -> dict:
        """Issue one request through the extension; return the `result` header.

        `req` carries the destination and the identity the extension applies --
        `target_host`, `target_port`, `tls`, `identity_id` -- and `body` is the
        raw HTTP request bytes. The returned dict is the result header plus the
        redacted response bytes under BODY_KEY.

        Enforcement is the extension's (S4: every byte that leaves this machine
        crosses one of two points inside the JVM). Everything refused here is
        refused a second time there; nothing allowed here is thereby allowed.

        `enforce_locally=False` drops THIS side's three duplicate refusals --
        the durable halt, `state == "halted"`, and anything short of
        `configured` -- and nothing else.

        SAY THE FIRST ONE OUT LOUD, because the keyword reads like
        belt-and-braces and one of the three is not. Dropping the DURABLE HALT
        means this call goes out while an operator has stopped the run by hand.
        It is duplicated only while the two sides are looking at the SAME
        sentinel file: the extension polls whatever `-Dhx.halt_sentinel` names
        and this side writes `OperatorHalt.sentinel_path`, and the integration
        rig makes them one path deliberately. Point them at two paths and this
        keyword is not a duplicate at all -- it is the halt, off. It exists for one caller, the
        integration rig, and for one reason: those refusals are answered
        BEFORE the wire, so a test of the extension's gate written the obvious
        way writes ZERO frames to the socket, is satisfied by this side's own
        bookkeeping, and goes on passing with the extension wide open. It
        weakens nothing in production -- the extension refuses each of these a
        second time, which is the half that actually stands between the agent
        and the network -- and a caller passing it is asking to be answered by
        the JVM rather than by this dict of state.

        It is a KEYWORD on this method rather than a second code path in the
        rig because the rig used to own a copy of the error translation below,
        and a copy is what drifts: a new frame type or a renamed hint field
        would have been handled here and not there, silently, with every test
        that uses it still asserting the old shape.

        The reserved-key guard above is NOT part of it. That one catches a
        malformed call -- a bug, not a denial -- and there is no test worth
        writing that needs it off.

        Raises BridgeError. `.error_class` is the peer's class for an `error`
        frame; `timeout` when no reply arrives in time; `bridge_lost` when the
        peer disconnects with this send in flight; `not_configured` or `halted`
        when this side refuses before the wire; and None when the call itself
        was malformed, which is a bug rather than a denial.

        NOTHING RETRIES.
        """
        bad = self._RESERVED_SEND_KEYS.intersection(req)
        if bad:
            raise BridgeError(
                f"send() stamps {sorted(bad)} itself; a caller may not set "
                "them. An engagement_id from the caller in particular would "
                "address whichever extension answers, not this engagement's."
            )
        if enforce_locally:
            # The durable halt is consulted on EVERY send, not only at hello.
            # An operator can create the sentinel file from a shell while the
            # socket is dead or the agent has stopped responding -- S4 names
            # that as the reason the file exists -- and that halt has to work
            # with no frame ever arriving.
            if self.operator_halt.halted:
                raise BridgeError(f"halted: {self.operator_halt.reason}",
                                  error_class="halted")
            state = self.state
            if state == "halted":
                raise BridgeError("halted", error_class="halted")
            if state != "configured":
                # DENY-ALL is the initial and terminal state. "connected" is
                # not configured: no configure frame has been acknowledged, so
                # the extension would refuse this anyway, with not_configured.
                raise BridgeError(f"not configured: bridge state is {state!r}",
                                  error_class="not_configured")

        reply = self._request({"v": codec.PROTOCOL_VERSION, "t": "send",
                               "engagement_id": self.engagement_id, **req},
                              body, timeout=timeout)
        t = reply.get("t")
        if t == "result":
            return reply
        if t == "error":
            raise BridgeError(
                f"{reply.get('class', 'unspecified')}: "
                f"{reply.get('detail', '')}".rstrip(": "),
                error_class=reply.get("class"),
                retry_after_us=reply.get("retry_after_us"),
            )
        raise BridgeError(f"peer answered a send with a {t!r} frame")

    def halt(self, reason: str) -> None:
        # The durable record is armed BEFORE the frame goes out. If the send
        # fails, or the peer vanishes between the send and the commit below,
        # the halt still stands and the next hello re-asserts it. Arming
        # afterwards would make a dead socket -- the likeliest thing to be
        # wrong when someone hits stop -- the one path that loses the halt.
        self.operator_halt.halt(reason)
        # Same send-then-mutate shape as configure(), so the same guard: a
        # peer that disconnects between the send and this commit must not
        # leave state looking like anything other than what _reset() wrote.
        gen = self._generation
        self._send({"v": codec.PROTOCOL_VERSION, "t": "halt", "reason": reason})
        with self._lock:
            if gen != self._generation or self._conn is None:
                raise BridgeError("peer disconnected before halt completed")
            self.state = "halted"

    def resume(self) -> None:
        gen = self._generation
        self._send({"v": codec.PROTOCOL_VERSION, "t": "resume"})
        with self._lock:
            if gen != self._generation or self._conn is None:
                raise BridgeError("peer disconnected before resume completed")
            self.state = "configured" if self.config_epoch else "connected"
        # Disarmed only after the frame reached the wire AND the commit above
        # stood. Every failure before this point leaves the durable halt armed,
        # which is the direction S4 asks for: unknown state is stop. Only
        # resume re-arms issuance, and only a resume that actually got there.
        self.operator_halt.resume()
```

- [ ] **Step 3b: Test the commit guard so that removing it fails a test**

The guard above has three separable parts, and a test suite that passes with
any of them deleted is not guarding anything. Two earlier attempts at this
test passed for the wrong reason:

- a 60-iteration natural-timing test measured 0/60 because the accept thread
  happens to win the inner race on this machine, not because the gap was shut;
- a 20-iteration widened-window test accepted **any** `BridgeError`, so it was
  satisfied ~19 times in 20 by an unrelated round-1 mechanism — `_reset()`
  wakes pending waiters, so `_request()` itself raises `peer disconnected
  before replying to configure` and the widened window is never even reached.

Write these four instead. They take no locks, start no threads and sleep for
nothing: the reset happens **inside** the gap because the stub performs it
there, on the calling thread. Each asserts the specific message, so it cannot
be satisfied by a different failure.

```python
def _connected(srv):
    """Drive srv to state 'connected' and return the live client socket."""
    c = _client(srv.socket_path)
    c.sendall(codec.encode({"v": 1, "t": "hello", "ext_version": "0.1",
                            "pid": 1, "burp_version": "x",
                            "instance_id": "i-1", "engagement_id": "e-1"}))
    deadline = time.time() + 5
    while srv.state != "connected" and time.time() < deadline:
        time.sleep(0.005)
    assert srv.state == "connected"
    return c


def test_configure_refuses_to_commit_when_a_reset_ran_in_the_gap(srv):
    """The whole point of the guard, deterministically: no threads, no sleeps.
    The stub performs the disconnect inside the window between _request()
    returning and configure()'s commit."""
    c = _connected(srv)
    try:
        def stub_request(header, body=b""):
            srv._reset(srv._generation)
            return {"v": 1, "t": "configured", "id": 1, "config_epoch": 7}
        srv._request = stub_request

        with pytest.raises(server.BridgeError,
                           match="peer disconnected before configure completed"):
            srv.configure({"scope.include": ["https://a/*"]},
                          scope_sha256="x", profile="production")
        assert srv.state == "waiting"
        assert srv.config_epoch == 0
    finally:
        c.close()


def test_configure_refuses_to_commit_when_the_socket_slot_was_refilled(srv):
    """Deliberately white-box, and the only test that isolates the generation
    token. It refills self._conn without going through accept(), so the
    `_conn is None` clause cannot fire and only `gen != self._generation`
    is left to catch the stale commit. Delete `self._generation += 1` from
    _reset() and this test fails; that is what it exists for."""
    c = _connected(srv)
    successor, other = socket.socketpair()
    try:
        def stub_request(header, body=b""):
            srv._reset(srv._generation)
            srv._conn = successor          # slot refilled: _conn is NOT None
            return {"v": 1, "t": "configured", "id": 1, "config_epoch": 7}
        srv._request = stub_request

        with pytest.raises(server.BridgeError,
                           match="peer disconnected before configure completed"):
            srv.configure({"scope.include": ["https://a/*"]},
                          scope_sha256="x", profile="production")
        assert srv.state == "waiting"
        assert srv.config_epoch == 0
    finally:
        srv._conn = None
        successor.close()
        other.close()
        c.close()


def test_reset_advances_the_generation_it_guards_on(srv):
    """The invariant is internal, so test it internally rather than pretend a
    black-box test can see it."""
    g0 = srv._generation
    srv._reset(g0)
    assert srv._generation > g0, "a real reset must advance the generation"

    g1 = srv._generation
    srv.state = "configured"
    srv.config_epoch = 9
    srv._reset(g0)                          # stale token: must be a no-op
    assert srv._generation == g1
    assert srv.state == "configured" and srv.config_epoch == 9


def test_halt_and_resume_refuse_to_commit_after_a_reset_in_the_gap(srv):
    """halt()/resume() have the same send-then-mutate shape as configure(),
    so they get the same test. Without this, the guard on them is unexercised
    by the whole suite."""
    for method, message in (
        (lambda: srv.halt("operator"), "peer disconnected before halt completed"),
        (lambda: srv.resume(), "peer disconnected before resume completed"),
    ):
        c = _connected(srv)
        try:
            def stub_send(header, body=b""):
                srv._reset(srv._generation)
            srv._send = stub_send

            with pytest.raises(server.BridgeError, match=message):
                method()
            assert srv.state == "waiting"
        finally:
            del srv._send          # fall back to the real bound method
            c.close()


def test_halt_and_resume_commit_on_the_happy_path(srv):
    c = _connected(srv)
    try:
        srv.halt("operator asked")
        assert srv.state == "halted"
        reader = codec.FrameReader(c)
        header, _ = reader.read()
        assert header["t"] == "halt" and header["reason"] == "operator asked"

        srv.resume()
        assert srv.state == "connected"     # no config_epoch yet
        header, _ = reader.read()
        assert header["t"] == "resume"
    finally:
        c.close()
```

Then fix the existing widened-window test rather than deleting it — as a
stress test it still has value, but its oracle must be the property that
actually matters instead of the identity of the error. Rename it to
`test_configure_never_leaves_a_lying_state_under_stress`, drop the word
"deterministically" from its name and its docstring, and replace

```python
            assert isinstance(result["error"], server.BridgeError)
```

with the invariant it was always trying to state:

```python
            # Whichever mechanism fires, the forbidden outcome is the same:
            # state that claims a peer the server no longer has.
            assert not (srv.state == "configured" and srv._conn is None), (
                f"lying state after a disconnect mid-configure (result={result!r})"
            )
```

**Verification that these tests guard the code.** Run each sabotage, confirm
the named tests fail, then `git checkout -- src/hx/bridge/server.py`:

| Sabotage | Must fail |
|---|---|
| delete `self._generation += 1` from `_reset()` | `..._socket_slot_was_refilled`, `test_reset_advances_the_generation...` |
| replace the three guards with `if False:` | `..._reset_ran_in_the_gap`, `..._socket_slot_was_refilled`, `test_halt_and_resume_refuse...` |
| delete `or self._conn is None` from the three guards | **nothing** — see below |

That third row is expected and must not be "fixed" by inventing a test for
it. `self._conn` is written in exactly two places — `_serve()` sets it
immediately after bumping the generation, `_reset()` nulls it immediately
after bumping the generation — so `_conn is None` always implies a
generation mismatch has already happened. The clause is redundant *given*
the generation bump. Keep it anyway: it costs nothing, it states the
invariant at the point of use, and it stops being redundant the moment
anyone adds a reconnect path that reuses the slot. The comment in
`configure()` already says exactly this; leave it there.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_bridge_server.py -v`
Expected: PASS, at least 18 passed — 13 from Steps 1-3 plus Step 3b's 5. The
file will hold more than that if a fix round added tests of its own (it did:
the real count at the end of Task 3 is 22). Treat 18 as a floor, never as a
target to trim tests down to.

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
- Modify: `extension/src/hx/bridge/Frame.java` — add `PeerClosed` and `Reader`, delete `read(InputStream)` (Step 0)
- Modify: `extension/test/hx/bridge/CodecTest.java` — the one call to the deleted method, plus the Reader's own tests (Step 0)
- Modify: `extension/test.sh` — run both test classes

**Interfaces:**
- Consumes: `hx.bridge.Frame`, `hx.bridge.Json`, `hx.bridge.ConfigBody` (Task 2)
- Produces:
  - `hx.bridge.BridgeClient(Path socketPath, String engagementId, String instanceId, BridgeClient.Log log)`
  - `hx.bridge.BridgeClient.Log` — `info(String)` / `error(String)`; Montoya's `Logging` is adapted to it in `HxExtension`, the test fake implements it directly
  - `BridgeClient.connect()` / `BridgeClient.close()`
  - `BridgeClient.isConfigured() -> boolean`
  - `BridgeClient.maySend() -> boolean` — configured and not halted
  - `BridgeClient.authorisation() -> BridgeClient.Authorisation` — **the only
    coherent way to read a decision.** Epoch and scope in ONE read
  - `hx.bridge.BridgeClient.Authorisation(long epoch, Map<String,List<String>> scope)`
    — a record; `scope` is deeply immutable
  - `BridgeClient.configEpoch() -> long` — **@Deprecated, do not use on a
    decision path**
  - `BridgeClient.scopeConfig() -> Map<String,List<String>>` — **@Deprecated**,
    same reason: calling these two separately is two reads of one record and a
    commit lands between them. The natural order, `scopeConfig()` then
    `configEpoch()`, measured wrong in 393/400 trials and wrong in the unsafe
    direction — decide under the superseded wider scope, stamp it with the
    epoch that narrowed it
  - `BridgeClient.checkMaySend() -> void` — throws `NotConfigured` unless configured and not halted
  - `hx.bridge.BridgeClient.NotConfigured extends RuntimeException`
  - `hx.HxExtension implements BurpExtension`

- [ ] **Step 0: `Frame.Reader` — a bare `read(InputStream)` cannot be correct in a loop**

`Frame.read(InputStream)` buffers into a **call-local** `ByteArrayOutputStream`.
When one delivery carries two frames it returns the first and drops the rest of
the buffer on the floor. Task 3's `readLoop()` calls it in a `while (true)`, so
every control frame that arrives coalesced with its predecessor is lost, and the
loss surfaces later as a misleading "peer closed mid-frame". Proven before this
step was written:

```
frame 1: t=configure
frame 2: LOST -> Incomplete("peer closed mid-frame")
```

This is the same defect the Python codec already fixed in Task 1, for the same
reason — `codec.FrameReader` exists because "a bare `read_frame(sock)` function
cannot be correct here". The Java side never got the equivalent. Add it, and
delete the trap rather than documenting it: a method that is correct exactly
once per stream and silently lossy on every later call is not worth keeping.

**Delete** `public static Decoded read(InputStream in)` from
`extension/src/hx/bridge/Frame.java` entirely and add `PeerClosed` and
`Reader` in its place. The full, current `Frame.java` is in Task 2's code
block — including two refinements that came out of Task 4's review and are
part of the final file: the shrink policy at line `buf.length > (1 << 22)`
(without hysteresis it re-doubled the buffer on every large frame: 115 ms vs
47 ms over 200 x 2 MB) and the note that a `Reader` belongs to exactly one
thread, since the hoisted `chunk` field is shared staging.

Do not transcribe a second copy here: an earlier version of this plan carried
the Reader twice and the two drifted apart the moment one was fixed.

`PeerClosed` is new, and deliberately distinct from `Incomplete`: `Incomplete`
means "call again with more bytes", which the Reader now handles internally and
never surfaces. It mirrors the Python `PeerClosed`, including both messages —
`"peer closed"` at a frame boundary is an orderly shutdown, `"peer closed
mid-frame"` is a truncated frame.

**Update the one existing caller** in `extension/test/hx/bridge/CodecTest.java`
(`readReassemblesAcrossChunks`):

```java
        Frame.Decoded d = new Frame.Reader(new ByteArrayInputStream(raw)).read();
```

**Add these to `CodecTest`**, using its existing `check(...)` helper, and call
them from `main` alongside the others:

```java
    static void readerKeepsCoalescedFrames() throws Exception {
        byte[] f1 = Frame.encode(Map.of("v", 1L, "t", "configure"), new byte[0]);
        byte[] f2 = Frame.encode(Map.of("v", 1L, "t", "halt"), "body".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream both = new ByteArrayOutputStream();
        both.write(f1); both.write(f2);

        Frame.Reader r = new Frame.Reader(new ByteArrayInputStream(both.toByteArray()));
        check("coalesced frame 1", "configure".equals(r.read().header.get("t")));
        Frame.Decoded second = r.read();
        // The whole point: a call-local buffer loses this one.
        check("coalesced frame 2 survives", "halt".equals(second.header.get("t")));
        check("coalesced frame 2 body intact",
              "body".equals(new String(second.body, StandardCharsets.UTF_8)));
    }

    static void readerSurvivesArbitraryChunkBoundaries() throws Exception {
        byte[] f1 = Frame.encode(Map.of("v", 1L, "t", "configure"), new byte[0]);
        byte[] f2 = Frame.encode(Map.of("v", 1L, "t", "halt"), "body".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream three = new ByteArrayOutputStream();
        three.write(f1); three.write(f2); three.write(f1);
        final byte[] all = three.toByteArray();

        InputStream sevenAtATime = new InputStream() {
            int i = 0;
            public int read() { return i < all.length ? (all[i++] & 0xff) : -1; }
            public int read(byte[] b, int off, int l) {
                if (i >= all.length) return -1;
                int n = Math.min(7, Math.min(l, all.length - i));
                System.arraycopy(all, i, b, off, n); i += n; return n;
            }
        };
        Frame.Reader r = new Frame.Reader(sevenAtATime);
        check("7-byte chunks: frame 1", "configure".equals(r.read().header.get("t")));
        check("7-byte chunks: frame 2", "halt".equals(r.read().header.get("t")));
        check("7-byte chunks: frame 3", "configure".equals(r.read().header.get("t")));
    }

    static void readerDistinguishesCleanCloseFromTruncation() throws Exception {
        byte[] f1 = Frame.encode(Map.of("v", 1L, "t", "configure"), new byte[0]);

        Frame.Reader clean = new Frame.Reader(new ByteArrayInputStream(f1));
        clean.read();
        boolean ok = false;
        try { clean.read(); } catch (Frame.PeerClosed e) { ok = "peer closed".equals(e.getMessage()); }
        check("clean close at a frame boundary is not an error condition", ok);

        byte[] truncated = Arrays.copyOfRange(f1, 0, f1.length - 3);
        ok = false;
        try { new Frame.Reader(new ByteArrayInputStream(truncated)).read(); }
        catch (Frame.PeerClosed e) { ok = "peer closed mid-frame".equals(e.getMessage()); }
        check("a truncated frame is reported as mid-frame", ok);
    }

    static void readerRejectsAnOversizedPrefixBeforeAllocating() throws Exception {
        byte[] huge = new byte[] {(byte) 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff, 'x'};
        boolean ok = false;
        try { new Frame.Reader(new ByteArrayInputStream(huge)).read(); }
        catch (Frame.FrameError e) { ok = e.getMessage().contains("exceeds MAX_FRAME"); }
        check("oversized length prefix rejected before allocation", ok);
    }
```

Run `extension/test.sh`. All of `CodecTest` must pass, including the four new
methods. Every one of these was run against the real `Frame` class before being
written here.

Commit this step on its own — it is a codec fix, not extension work:

```bash
git add extension/src/hx/bridge/Frame.java extension/test/hx/bridge/CodecTest.java
git commit -m "fix(codec): a call-local buffer drops frames that arrive coalesced"
```

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

    /** StringBuffer, not StringBuilder: the bridge logs from its read-loop
     *  thread while the test reads from main. StringBuilder is not thread-safe,
     *  so that pairing can lose or corrupt a line -- in the one assertion that
     *  proves the deny-all transition was announced. */
    public static final class Logger implements BridgeClient.Log {
        public final StringBuffer out = new StringBuffer();
        public final StringBuffer err = new StringBuffer();
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

import static hx.TestSupport.waitUntilBlockedOn;

import hx.TestSupport;
import hx.send.HaltSwitch;

import java.io.*;
import java.net.*;
import java.nio.channels.Channel;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Drives BridgeClient against a fake Python server on a real unix socket. */
public class BridgeClientTest {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    /** Runs one test method under the shared per-method guard: a throw out of
     *  it becomes a named FAIL against THIS class's counter instead of ending
     *  main() with the methods after it unrun and no summary line printed.
     *  See {@link hx.TestSupport#t}. */
    static void t(String name, TestSupport.Body body) {
        TestSupport.t(BridgeClientTest::check, name, body);
    }

    /**
     * Every blocking socket operation in this file carries a deadline.
     *
     * This is the third way a hand-rolled runner truncates, and the worst of
     * them. A sabotage that stops BridgeClient sending its hello used to park
     * the first {@code reader.read()} on the socket FOREVER: zero lines of
     * output, no summary line, and no exit code at all -- a result that under
     * {@code ./test.sh | grep -c FAIL} reads as zero failures, and a runner
     * that has to be killed from outside. `timeout` in test.sh bounds the
     * damage; it does not make the test report anything. A guard that can only
     * be stopped by an outside stopwatch is not guarding.
     *
     * Ten seconds is twenty-five times the whole class's measured runtime
     * (381 ms), and twice the 5 s bound {@link #waitUntil} already carries, so
     * it can only fire on a genuine wedge. It also has to leave room for the
     * WORST case rather than the typical one: every method wedging in turn
     * costs one deadline each, and that total must stay inside test.sh's 300 s
     * backstop -- 10 s buys thirty methods, against nine today.
     */
    static final long READ_DEADLINE_MS = 10_000L;

    /**
     * A unix-domain {@link SocketChannel} has no SO_TIMEOUT, so the deadline is
     * a watchdog that CLOSES the channel out from under the parked call. The
     * blocked read or accept then throws, which the per-method guard turns into
     * a named FAIL. Whether the watchdog fired is recorded rather than inferred
     * from the exception type: an ordinary IOException from a test that is
     * doing its job must keep its own message.
     */
    static final class Deadline implements AutoCloseable {
        private final AtomicBoolean expired = new AtomicBoolean(false);
        private final Thread watchdog;

        Deadline(Channel ch) {
            watchdog = new Thread(() -> {
                try { Thread.sleep(READ_DEADLINE_MS); }
                catch (InterruptedException arrivedInTime) { return; }
                expired.set(true);
                try { ch.close(); } catch (IOException ignored) { }
            });
            watchdog.setDaemon(true);
            watchdog.start();
        }

        boolean expired() { return expired.get(); }

        public void close() { watchdog.interrupt(); }
    }

    /** {@code reader.read()} with a deadline on it. */
    static Frame.Decoded read(Frame.Reader reader, Channel ch, String what) throws Exception {
        try (Deadline d = new Deadline(ch)) {
            try {
                return reader.read();
            } catch (IOException e) {
                if (d.expired())
                    throw new IOException(what + " did not arrive within "
                                          + READ_DEADLINE_MS + " ms", e);
                throw e;
            }
        }
    }

    /** {@code server.accept()} with a deadline on it: a client that never
     *  dials wedges here exactly as a frame that never arrives wedges above. */
    static SocketChannel accept(ServerSocketChannel server) throws Exception {
        try (Deadline d = new Deadline(server)) {
            try {
                return server.accept();
            } catch (IOException e) {
                if (d.expired())
                    throw new IOException("the client did not dial within "
                                          + READ_DEADLINE_MS + " ms", e);
                throw e;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("hxbridge");
        Path sock = dir.resolve("t.sock");

        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(sock));

            FakeMontoya.Logger log = new FakeMontoya.Logger();
            BridgeClient client = new BridgeClient(sock, "e-1", "i-1", log);
            client.setHaltSource(NOTHING_HELD);

            // Daemon, for the same reason live()'s dial thread is one: a read
            // loop that outlives its assertions must not keep the JVM up after
            // main() has printed its summary.
            Thread dial = new Thread(() -> { try { client.connect(); } catch (Exception ignored) { } });
            dial.setDaemon(true);
            dial.start();

            t("theControlChannelHandshake", () -> theControlChannelHandshake(server, client));
            client.close();

            t("closedIsSticky", BridgeClientTest::closedIsSticky);
            t("aClosedClientDoesNotGoLive", BridgeClientTest::aClosedClientDoesNotGoLive);
            t("aRefusedConfigureDropsToDenyAll", BridgeClientTest::aRefusedConfigureDropsToDenyAll);
            t("closeIsTerminalAgainstTheReadLoop", BridgeClientTest::closeIsTerminalAgainstTheReadLoop);
            t("losingThePeerDropsToDenyAll", BridgeClientTest::losingThePeerDropsToDenyAll);
            t("aFailedHelloLeavesNoChannelBehind", BridgeClientTest::aFailedHelloLeavesNoChannelBehind);
            t("theCommitIsExclusiveWithClose", BridgeClientTest::theCommitIsExclusiveWithClose);
            t("aConfigureDoesNotLiftAHalt", BridgeClientTest::aConfigureDoesNotLiftAHalt);
            t("haltFramesReachTheSwitchTheSendPathAsks", BridgeClientTest::haltFramesReachTheSwitchTheSendPathAsks);
            t("theKillPathsThatNeverTouchTheLocalFlagStillDenySending",
              BridgeClientTest::theKillPathsThatNeverTouchTheLocalFlagStillDenySending);
            t("aConfigureTheGuardRefusesIsBadConfigAndKeepsTheChannel",
              BridgeClientTest::aConfigureTheGuardRefusesIsBadConfigAndKeepsTheChannel);
            t("aHaltFrameWithNoReasonDoesNotDeliverTheWordNull", BridgeClientTest::aHaltFrameWithNoReasonDoesNotDeliverTheWordNull);
            t("aHaltSinkThatThrowsDropsToDenyAll", BridgeClientTest::aHaltSinkThatThrowsDropsToDenyAll);
            t("theSendArmHandsTheHandlerOneCoherentAuthorisation", BridgeClientTest::theSendArmHandsTheHandlerOneCoherentAuthorisation);
            t("aSendForAnotherEngagementNeverReachesTheHandler", BridgeClientTest::aSendForAnotherEngagementNeverReachesTheHandler);
            t("aSendHandlerThatThrowsDropsToDenyAll", BridgeClientTest::aSendHandlerThatThrowsDropsToDenyAll);
            t("aSendWithNoHandlerInstalledIsRefused", BridgeClientTest::aSendWithNoHandlerInstalledIsRefused);
            t("aThrowingSendArmBothDeniesAndStopsTheLoop",
              BridgeClientTest::aThrowingSendArmBothDeniesAndStopsTheLoop);
            t("anUnusableLimitIsRefusedAtConfigureTimeAndTheChannelSurvives",
              BridgeClientTest::anUnusableLimitIsRefusedAtConfigureTimeAndTheChannelSurvives);
            t("theExchangeSinkFramesBothHalves",
              BridgeClientTest::theExchangeSinkFramesBothHalves);
            t("theExchangeSinkNeverRaisesIntoCapture",
              BridgeClientTest::theExchangeSinkNeverRaisesIntoCapture);
        } finally {
            Files.deleteIfExists(sock);
            Files.deleteIfExists(dir);
        }

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILURE(S)");
        if (failures > 0) System.exit(1);
    }

    /**
     * The first connection, end to end: hello, the DENY-ALL that precedes any
     * configure, the configure itself, halt/resume, and the two frames that
     * must be refused. A method rather than an inline block in main() so that
     * the per-method guard covers it -- inline, a single throw in here (an
     * unanswered read, a null header) took the other eight methods with it.
     */
    static void theControlChannelHandshake(ServerSocketChannel server, BridgeClient client)
            throws Exception {
        try (SocketChannel peer = accept(server)) {
            InputStream in = java.nio.channels.Channels.newInputStream(peer);
            OutputStream out = java.nio.channels.Channels.newOutputStream(peer);
            // One Reader for the whole connection: frames coalesce, and a
            // fresh reader per call would drop whatever followed the one
            // it returned.
            Frame.Reader reader = new Frame.Reader(in);

            // 1. hello arrives with the right identity
            Frame.Decoded hello = read(reader, peer, "the hello");
            check("sends hello", "hello".equals(hello.header.get("t")));
            check("hello carries engagement_id", "e-1".equals(hello.header.get("engagement_id")));
            check("hello carries instance_id", "i-1".equals(hello.header.get("instance_id")));
            check("hello carries protocol version", Long.valueOf(1L).equals(hello.header.get("v")));

            // 2. DENY-ALL before configure
            check("unconfigured after hello", !client.isConfigured());
            boolean threw = false;
            try { client.checkMaySend(); } catch (BridgeClient.NotConfigured e) { threw = true; }
            check("checkMaySend throws NotConfigured before configure", threw);
            // ...and the other side of the overload: an operator who has not
            // configured is not an extension fault, so the prefix must NOT be
            // there. A marker every not_configured carries marks nothing.
            String beforeConfigure = null;
            try { client.checkMaySend(); }
            catch (BridgeClient.NotConfigured e) { beforeConfigure = e.getMessage(); }
            check("and an unconfigured operator is not marked an extension fault ("
                  + beforeConfigure + ")",
                  beforeConfigure != null
                  && !beforeConfigure.contains(BridgeClient.EXTENSION_FAULT));

            // 3. configure -> configured, with an epoch
            Map<String, Object> cfg = new LinkedHashMap<>();
            cfg.put("v", 1L); cfg.put("t", "configure"); cfg.put("id", 1L);
            cfg.put("engagement_id", "e-1"); cfg.put("scope_sha256", "abc");
            cfg.put("profile", "production");
            // configure is the one request frame, and BridgeServer._request
            // stamps id and deadline_us onto every one of them. A fake that
            // omits it is not the peer: the client answers bad_frame.
            cfg.put("deadline_us", System.currentTimeMillis() * 1000L + 10_000_000L);
            out.write(Frame.encode(cfg, "scope.include\thttps://a/*\nlimit.rate_rps\t5\n"
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            out.flush();

            Frame.Decoded ack = read(reader, peer, "the configured ack");
            check("acks with configured", "configured".equals(ack.header.get("t")));
            check("ack echoes the request id", Long.valueOf(1L).equals(ack.header.get("id")));
            check("ack carries a non-zero epoch",
                  ((Long) ack.header.get("config_epoch")) > 0);

            waitUntil(() -> client.isConfigured());
            check("configured after ack", client.isConfigured());
            check("scope config parsed",
                  client.scopeConfig().get("scope.include").equals(List.of("https://a/*")));
            // The coherent read. configEpoch() then scopeConfig() is two
            // volatile reads and a commit can land between them; this is
            // the one an evidence line has to use.
            BridgeClient.Authorisation au = client.authorisation();
            check("authorisation() carries the epoch and the scope together",
                  au.epoch() == client.configEpoch()
                  && au.scope().equals(client.scopeConfig()));
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
            boolean resumed = client.maySend();
            try { client.checkMaySend(); } catch (BridgeClient.NotConfigured e) { resumed = false; }
            check("resume unblocks sending", resumed);

            // 5. an engagement_id mismatch on configure is refused
            Map<String, Object> wrong = new LinkedHashMap<>(cfg);
            wrong.put("id", 2L); wrong.put("engagement_id", "SOMEONE-ELSE");
            out.write(Frame.encode(wrong, new byte[0])); out.flush();
            Frame.Decoded err = read(reader, peer, "the engagement-mismatch error");
            check("engagement mismatch answered with error",
                  "error".equals(err.header.get("t")));
            check("error class names the mismatch",
                  String.valueOf(err.header.get("class")).contains("engagement"));

            // 6. a protocol-mismatch frame while configured must trip
            // DENY-ALL through readLoop's OTHER exit path. handle()
            // returns false here, and the bare `return` that used to
            // follow skipped both catch blocks entirely: configured
            // stayed true, configEpoch kept its value, and maySend()
            // would answer true forever with a dead read loop and no
            // control channel behind it. This is the exact leak the
            // finally block in readLoop() exists to close.
            check("configured before the protocol-mismatch frame", client.maySend());
            Map<String, Object> badVersion = new LinkedHashMap<>();
            badVersion.put("v", 2L); badVersion.put("t", "halt"); badVersion.put("reason", "operator");
            out.write(Frame.encode(badVersion, new byte[0])); out.flush();
            Frame.Decoded mismatch = read(reader, peer, "the protocol-mismatch error");
            check("protocol mismatch answered with error",
                  "error".equals(mismatch.header.get("t")));
            check("error class names the protocol mismatch",
                  "protocol_mismatch".equals(mismatch.header.get("class")));
            waitUntil(() -> !client.maySend());
            check("protocol mismatch trips DENY-ALL via readLoop's return path",
                  !client.maySend());
            boolean deniedAfterMismatch = false;
            try { client.checkMaySend(); }
            catch (BridgeClient.NotConfigured e) { deniedAfterMismatch = true; }
            check("checkMaySend throws after the protocol-mismatch DENY-ALL",
                  deniedAfterMismatch);
        }
    }

    /** Drive a fresh client to "configured" and hand back the pieces. */
    static final class Live implements AutoCloseable {
        final BridgeClient client; final SocketChannel peer;
        final OutputStream out; final Frame.Reader reader; final FakeMontoya.Logger log;
        final ServerSocketChannel server;
        Live(ServerSocketChannel server, BridgeClient c, SocketChannel p,
             OutputStream o, Frame.Reader r, FakeMontoya.Logger l) {
            this.server = server; this.client = c; this.peer = p;
            this.out = o; this.reader = r; this.log = l;
        }
        public void close() throws Exception {
            client.close(); peer.close(); server.close();
        }
    }

    static Map<String, Object> configureFrame(String engagement, long id) {
        Map<String, Object> cfg = new LinkedHashMap<>();
        cfg.put("v", 1L); cfg.put("t", "configure"); cfg.put("id", id);
        cfg.put("engagement_id", engagement); cfg.put("scope_sha256", "abc");
        cfg.put("profile", "production");
        cfg.put("deadline_us", System.currentTimeMillis() * 1000L + 10_000_000L);
        return cfg;
    }

    static Live live(Path dir, String name) throws Exception {
        Path sock = dir.resolve(name);
        ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        server.bind(UnixDomainSocketAddress.of(sock));
        FakeMontoya.Logger log = new FakeMontoya.Logger();
        BridgeClient client = new BridgeClient(sock, "e-1", "i-1", log);
        client.setHaltSource(NOTHING_HELD);
        // Daemon: a read loop that leaks past the end of a test must fail the
        // suite by way of its assertions, not outlive main() and hang the JVM.
        Thread dial = new Thread(() -> { try { client.connect(); } catch (Exception ignored) { } });
        dial.setDaemon(true);
        dial.start();
        SocketChannel peer = accept(server);
        OutputStream out = java.nio.channels.Channels.newOutputStream(peer);
        Frame.Reader reader = new Frame.Reader(java.nio.channels.Channels.newInputStream(peer));
        read(reader, peer, "the hello");
        out.write(Frame.encode(configureFrame("e-1", 1L),
                  "scope.include\thttps://WIDE/*\n".getBytes(StandardCharsets.UTF_8)));
        out.flush();
        read(reader, peer, "the configured ack");
        waitUntil(client::isConfigured);
        return new Live(server, client, peer, out, reader, log);
    }

    /**
     * A halt source that never holds issuance.
     *
     * BridgeClient fails CLOSED without one -- see setHaltSource -- so every
     * client built here installs this, and the checks below are then about
     * THIS class's own two flags with the send path's authority held constant.
     * The tests that vary the authority instead install their own; see
     * theKillPathsThatNeverTouchTheLocalFlagStillDenySending.
     */
    static final BridgeClient.HaltSource NOTHING_HELD = () -> null;

    /** close() must be sticky: a client closed before its dial completes must
     *  never go on to hello, configure and live sending. Reproduced by the
     *  review as an UNLOADED extension holding a control channel. */
    static void closedIsSticky() throws Exception {
        Path dir = Files.createTempDirectory("hxsticky");
        Path sock = dir.resolve("s.sock");
        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(sock));
            BridgeClient client = new BridgeClient(sock, "e-1", "i-1", new FakeMontoya.Logger());
            client.setHaltSource(NOTHING_HELD);
            client.close();

            // On a thread with a join timeout: an unfixed client's connect()
            // dials, sends hello and blocks in readLoop forever, so a direct
            // call would hang the suite instead of failing it.
            final boolean[] refused = {false};
            Thread dial = new Thread(() -> {
                try { client.connect(); }
                catch (IOException e) { refused[0] = true; }
                catch (Exception ignored) { }
            });
            dial.setDaemon(true);
            dial.start();
            dial.join(3000);

            check("connect() on a closed client returns instead of dialling", !dial.isAlive());
            check("connect() on a closed client is refused", refused[0]);
            check("a closed client never reports maySend", !client.maySend());
        } finally {
            Files.deleteIfExists(sock); Files.deleteIfExists(dir);
        }
    }

    /** A configure arriving after close() must not resurrect the client. */
    static void aClosedClientDoesNotGoLive() throws Exception {
        Path dir = Files.createTempDirectory("hxresurrect");
        try (Live l = live(dir, "r.sock")) {
            check("live before close", l.client.maySend());
            l.client.close();
            check("closed client denies immediately", !l.client.maySend());

            // A second configure lands after close(): the read loop must not
            // act on it.
            try {
                l.out.write(Frame.encode(configureFrame("e-1", 2L),
                        "scope.include\thttps://SNEAKY/*\n".getBytes(StandardCharsets.UTF_8)));
                l.out.flush();
            } catch (IOException ignored) { /* channel already shut: also fine */ }
            Thread.sleep(150);
            check("a configure after close() does not resurrect the client", !l.client.maySend());
            check("and leaves no epoch behind", l.client.configEpoch() == 0);
            check("and leaves no scope behind", l.client.scopeConfig().isEmpty());

            // The same property without a race in it. closeIsTerminalAgainst-
            // TheReadLoop() below can only catch the defect when the scheduler
            // cooperates -- measured 0/20 on ONE core against 11-14/20 on 24 --
            // and CI runners are commonly 2 vCPU, so on its own that guard can
            // go quietly vacuous. This one cannot: it hands handle() a frame
            // directly on this thread, on a client that was configured before
            // close(), and it must be refused.
            boolean refused;
            try {
                refused = !l.client.handle(
                        Frame.decode(Frame.encode(configureFrame("e-1", 9L), CFG)));
            } catch (IOException e) {
                // It got as far as writing an ack down a channel close() shut,
                // which means it did not refuse the frame. Caught so this
                // reports as a failed check rather than killing the runner
                // part-way through the suite.
                refused = false;
            }
            check("handle() refuses a frame on a closed client", refused);
            check("and did not re-enable sending", !l.client.maySend());
        } finally {
            Files.deleteIfExists(dir.resolve("r.sock")); Files.deleteIfExists(dir);
        }
    }

    /** A configure we cannot parse means the operator's intent is unknown.
     *  Keeping the PREVIOUS, wider scope would send exactly where a narrowing
     *  operator just said not to. */
    static void aRefusedConfigureDropsToDenyAll() throws Exception {
        Path dir = Files.createTempDirectory("hxbadcfg");
        try (Live l = live(dir, "b.sock")) {
            check("wide scope is in force first",
                  l.client.scopeConfig().toString().contains("WIDE"));

            l.out.write(Frame.encode(configureFrame("e-1", 3L),
                    "this-is-not-a-config-body\n".getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded err = read(l.reader, l.peer, "the config error");
            check("unparseable configure is answered with an error",
                  "error".equals(err.header.get("t")));
            check("error class names the config",
                  String.valueOf(err.header.get("class")).contains("config"));

            waitUntil(() -> !l.client.maySend());
            check("a refused configure drops to DENY-ALL", !l.client.maySend());
            check("the superseded wider scope is dropped", l.client.scopeConfig().isEmpty());
            check("and its epoch with it", l.client.configEpoch() == 0);
        } finally {
            Files.deleteIfExists(dir.resolve("b.sock")); Files.deleteIfExists(dir);
        }
    }

    /** The most common terminal path of all, and previously untested. */
    static void losingThePeerDropsToDenyAll() throws Exception {
        Path dir = Files.createTempDirectory("hxpeergone");
        try (Live l = live(dir, "p.sock")) {
            check("configured while the peer is up", l.client.maySend());
            l.peer.close();

            waitUntil(() -> !l.client.maySend());
            check("losing the peer drops to DENY-ALL", !l.client.maySend());
            check("epoch zeroed on peer loss", l.client.configEpoch() == 0);
            check("scope dropped on peer loss", l.client.scopeConfig().isEmpty());
            // maySend() flipping is not a happens-before edge for the log line:
            // denyAll() lands two statements before log.info(). Wait on the
            // thing being asserted.
            waitUntil(() -> l.log.sawInfo("deny-all"));
            check("and the transition is logged",
                  l.log.sawInfo("deny-all"));
        } finally {
            Files.deleteIfExists(dir.resolve("p.sock")); Files.deleteIfExists(dir);
        }
    }

    /**
     * close() must be terminal the instant it returns. The read loop runs on
     * its own thread and may be part-way through a `configure` that was
     * already sitting in the Reader's buffer when close() ran; if the commit
     * is not exclusive with close(), the loop sets configured back to true
     * behind close()'s back and maySend() answers true for as long as it takes
     * to write the ack -- microseconds in which Plan 3 will send.
     *
     * Two details are load-bearing, both learned the hard way. A COALESCED
     * BACKLOG of configure frames, because with one there is nothing for
     * close() to race. And a BUSY POLL, because the window opens a few us
     * AFTER close() returns: a sample at t=0 lands before it, a sample at
     * t=2ms lands after it, and both report all-clear. Point samples measured
     * 0/40 on code that a poll catches 39/40.
     *
     * This is a DETECTOR, not the guard. It is scheduler-dependent: against
     * the defective client the review measured 11-14/20 on 24 cores, 1-3/20 on
     * two, and 0/20 pinned to one -- so on a 2-vCPU CI runner it can pass
     * clean on broken code. The guard is the deterministic handle()-after-
     * close() check in aClosedClientDoesNotGoLive(). A 64-frame backlog and
     * an ack read before close() (which proves the loop is already chewing
     * through the backlog rather than parked on the socket) took the detector
     * to 18-20/20 on multi-core without losing the 2-core signal.
     */
    static void closeIsTerminalAgainstTheReadLoop() throws Exception {
        Path dir = Files.createTempDirectory("hxclose");
        int resurrections = 0, attempts = 20;
        try {
            for (int i = 0; i < attempts; i++) {
                Path sock = dir.resolve("c" + i + ".sock");
                try (ServerSocketChannel server =
                             ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
                    server.bind(UnixDomainSocketAddress.of(sock));
                    BridgeClient client =
                            new BridgeClient(sock, "e-1", "i-1", new FakeMontoya.Logger());
                    client.setHaltSource(NOTHING_HELD);
                    Thread t = new Thread(() -> {
                        try { client.connect(); } catch (Exception ignored) { } });
                    t.setDaemon(true);
                    t.start();
                    try (SocketChannel peer = accept(server)) {
                        OutputStream out = java.nio.channels.Channels.newOutputStream(peer);
                        Frame.Reader reader =
                                new Frame.Reader(java.nio.channels.Channels.newInputStream(peer));
                        read(reader, peer, "the hello");

                        out.write(Frame.encode(configureFrame("e-1", 0L), CFG));
                        out.flush();
                        read(reader, peer, "the configured ack");
                        waitUntil(client::isConfigured);

                        ByteArrayOutputStream backlog = new ByteArrayOutputStream();
                        for (int j = 1; j <= BACKLOG; j++)
                            backlog.write(Frame.encode(configureFrame("e-1", j), CFG));
                        out.write(backlog.toByteArray()); out.flush();

                        // Gate on the first ack: it says the read loop has the
                        // whole backlog in its Reader and is committing frames
                        // out of it, so close() lands mid-backlog rather than
                        // before the bytes have even arrived.
                        read(reader, peer, "the first backlog ack");

                        client.close();

                        long end = System.nanoTime() + 5_000_000L;       // 5 ms
                        while (System.nanoTime() < end)
                            if (client.maySend()) { resurrections++; break; }
                    }
                }
                Files.deleteIfExists(sock);
            }
        } finally {
            Files.deleteIfExists(dir);
        }
        check("close() is terminal: the read loop cannot re-enable sending behind it ("
              + resurrections + "/" + attempts + " resurrections)", resurrections == 0);
    }

    /** Frames left buffered in the client's Reader when close() lands. Two was
     *  enough to see the defect on a busy machine and nowhere near enough on a
     *  quiet one. */
    static final int BACKLOG = 64;

    /**
     * F6: a dialled channel must not outlive a failed hello. Reverting the
     * closeChannel() in connect()'s catch failed nothing before this existed --
     * an unloadable extension would hold an open control channel with no
     * reader on it, and connect()'s caller would have no way to shut it.
     *
     * Deterministic, not a race, and the instance_id is what makes it so. At
     * 8 MB the hello cannot fit in the socket buffer (212992 bytes here), so
     * the write BLOCKS. Whether the peer's close lands before the write starts
     * or while it is parked, the write fails; there is no interleaving in
     * which it quietly succeeds and the client sails on into readLoop().
     */
    static void aFailedHelloLeavesNoChannelBehind() throws Exception {
        Path dir = Files.createTempDirectory("hxhello");
        Path sock = dir.resolve("h.sock");
        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(sock));
            BridgeClient client = new BridgeClient(
                    sock, "e-1", "i-".repeat(4 << 20), new FakeMontoya.Logger());
            client.setHaltSource(NOTHING_HELD);

            Thread killer = new Thread(() -> {
                try (SocketChannel peer = server.accept()) {
                    // Accepted and dropped on the floor: nothing will ever
                    // drain this hello.
                } catch (IOException ignored) { }
            });
            killer.setDaemon(true);
            killer.start();

            boolean threw = false;
            try { client.connect(); } catch (Exception e) { threw = true; }
            killer.join(5000);

            check("a hello that cannot be written propagates out of connect()", threw);
            check("and the dialled channel does not outlive the failed hello",
                  !client.channelIsOpen());
            check("and the client is still denying", !client.maySend());
        } finally {
            Files.deleteIfExists(sock); Files.deleteIfExists(dir);
        }
    }

    /**
     * The commit-lock guard, deterministically. The top-of-handle() guard
     * cannot satisfy this one: the frame is already past it and parked on the
     * monitor when close() runs.
     *
     * Monitor reentrancy is what makes it deterministic. This thread holds
     * commitLock, so the helper cannot get past `synchronized (commitLock)` in
     * handle(); close() takes the SAME monitor and this thread already owns it,
     * so it proceeds. When this block exits, the helper acquires the monitor
     * and must observe `closed`.
     *
     * The park is verified by LOCK IDENTITY, not by Thread.State alone: a
     * thread stuck on a class-initialisation monitor is also BLOCKED, and
     * accepting that would let the helper still be BEFORE the top-of-handle()
     * guard when close() lands -- which passes for the wrong reason and stops
     * covering the commit-lock guard at all.
     */
    static void theCommitIsExclusiveWithClose() throws Exception {
        Path dir = Files.createTempDirectory("hxexcl");
        try (Live l = live(dir, "x.sock")) {
            final boolean[] refused = {false};
            Thread t;
            synchronized (l.client.commitLock) {
                t = new Thread(() -> {
                    try { refused[0] = !l.client.handle(
                            Frame.decode(Frame.encode(configureFrame("e-1", 7L), CFG))); }
                    catch (IOException e) { refused[0] = false; }
                });
                t.setDaemon(true);
                t.start();
                check("the configure is parked on commitLock itself",
                      waitUntilBlockedOn(t, l.client.commitLock));
                l.client.close();          // reentrant: this thread holds the monitor
            }
            t.join(5000);
            check("a commit parked on commitLock is refused once close() has run", refused[0]);
            check("and close() stays terminal", !l.client.maySend());
        } finally {
            Files.deleteIfExists(dir.resolve("x.sock")); Files.deleteIfExists(dir);
        }
    }

    /**
     * A configure frame must NOT lift an operator halt. The commit used to end
     * with `halted.set(false)`, so the most likely next action after halting --
     * halt because the scope went wrong, push the corrected scope -- re-armed
     * issuance with no resume() on the wire, no log line, and both consoles
     * reading "configured".
     *
     * The other half of the assertion matters just as much: the epoch and the
     * scope must still commit. Narrowing scope during an emergency stop is
     * exactly what an operator should be able to do, so "configure is refused
     * while halted" would be the wrong fix. A configure re-authorises SCOPE,
     * not ISSUANCE.
     */
    static void aConfigureDoesNotLiftAHalt() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltcfg");
        try (Live l = live(dir, "h.sock")) {              // configured, epoch 1, WIDE
            check("configured before the halt", l.client.maySend());

            l.out.write(Frame.encode(
                    Map.of("v", 1L, "t", "halt", "reason", "scope was wrong"), new byte[0]));
            l.out.flush();
            waitUntil(() -> !l.client.maySend());
            check("halt blocks sending", !l.client.maySend());

            // The corrected, NARROWER scope, pushed while halted.
            l.out.write(Frame.encode(configureFrame("e-1", 4L),
                    "scope.include\thttps://NARROW/*\n".getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded ack = read(l.reader, l.peer,
                                     "the ack for the configure sent while halted");
            // Reading the ack is the happens-before edge: the commit completes
            // before the ack is written, so nothing below has to poll.
            check("the configure while halted is acknowledged",
                  "configured".equals(ack.header.get("t")));

            boolean stillHalted = false;
            String message = "";
            try { l.client.checkMaySend(); }
            catch (BridgeClient.NotConfigured e) { stillHalted = true; message = e.getMessage(); }
            check("a configure does not lift an operator halt", stillHalted);
            check("and the refusal still names the halt, not a missing configure ("
                  + message + ")", message.startsWith("halted:"));
            check("and maySend() agrees", !l.client.maySend());

            // ...while the scope and epoch it carried DID commit.
            BridgeClient.Authorisation au = l.client.authorisation();
            check("the configure still advanced the epoch (" + au.epoch() + ")",
                  au.epoch() == 2L);
            check("ack reports the advanced epoch",
                  Long.valueOf(2L).equals(ack.header.get("config_epoch")));
            check("the narrowed scope is in force",
                  au.scope().get("scope.include").equals(List.of("https://NARROW/*")));

            // And a resume -- the frame that IS allowed to re-arm issuance --
            // does so, under the epoch-2 scope.
            l.out.write(Frame.encode(Map.of("v", 1L, "t", "resume"), new byte[0]));
            l.out.flush();
            waitUntil(l.client::maySend);
            check("resume is what re-arms issuance", l.client.maySend());
        } finally {
            Files.deleteIfExists(dir.resolve("h.sock")); Files.deleteIfExists(dir);
        }
    }

    /**
     * A `halt` frame has to reach the switch the SEND PATH asks.
     *
     * BridgeClient's own `halted` flag guards maySend() and checkMaySend(),
     * and Sender calls neither: it asks HaltSwitch. Wired up wrongly -- or not
     * at all -- a halt frame would flip a flag nothing on the send path reads,
     * both consoles would say "halted", and requests would keep going out. The
     * failure has no other observable: maySend() answers false either way.
     */
    static void haltFramesReachTheSwitchTheSendPathAsks() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltsink");
        // Unstarted, so this test runs no poller thread: the sentinel half is
        // HaltSwitchTest's business, and the frame half needs no clock -- an
        // unarmed switch never reads one.
        HaltSwitch hs = new HaltSwitch(() -> 0L, dir.resolve("halt"), 500L);
        try (Live l = live(dir, "hs.sock")) {
            l.client.setHaltSink(new BridgeClient.HaltSink() {
                public void halted(String reason) { hs.haltedByFrame(reason); }
                public void resumed()             { hs.resumedByFrame(); }
            });
            check("the send path is not halted before the frame", !hs.halted());

            l.out.write(Frame.encode(
                    Map.of("v", 1L, "t", "halt", "reason", "operator pressed stop"), new byte[0]));
            l.out.flush();
            waitUntil(hs::halted);
            check("a halt frame halts the switch the send path asks", hs.halted());
            check("and the operator's words arrive with it",
                  "operator pressed stop".equals(hs.reason()));
            check("and the client's own flag agrees", !l.client.maySend());

            l.out.write(Frame.encode(Map.of("v", 1L, "t", "resume"), new byte[0]));
            l.out.flush();
            waitUntil(() -> !hs.halted());
            check("a resume frame lifts it on the send path too", !hs.halted());
            check("and the client is sending again", l.client.maySend());
        } finally {
            Files.deleteIfExists(dir.resolve("hs.sock")); Files.deleteIfExists(dir);
        }
    }

    /**
     * A configure the guard refuses is `bad_config`, leaves no epoch behind,
     * and keeps the channel.
     *
     * Spec s4, amended 2026-08-23: `Limits` takes the rate and budget from the
     * FIRST authorisation with an epoch and holds them, because the budget
     * must be monotonic -- a scope push must not resupply a run that has spent
     * its requests. So an operator pushing `limit.rate_rps: 1` mid-run because
     * the target is wobbling got a fresh `config_epoch`, no error, no log line
     * and the OLD RATE. Lowering a rate is the one change that is always safe;
     * believing you have made it when you have not is the failure to avoid.
     *
     * The guard installed here is a stand-in for
     * `Limits.refuseIfLimitsMoved`, so this file needs no hx.send import to
     * say what it has to say: that this client ASKS, that a refusal is
     * bad_config rather than an ack, and that the refusal happens BEFORE the
     * commit. The real predicate -- which configures move an armed limit and
     * which do not -- is SenderTest's, where Limits is.
     *
     * The epoch assertion is the one that pins the placement. Refusing after
     * the commit would still answer bad_config, and the operator would still
     * be told; what they would ALSO have is a fresh `config_epoch` stamped on
     * every later evidence line, granted by a configure that was refused.
     */
    static void aConfigureTheGuardRefusesIsBadConfigAndKeepsTheChannel() throws Exception {
        Path dir = Files.createTempDirectory("hxconfigguard");
        try (Live l = live(dir, "cg.sock")) {
            long armed = l.client.authorisation().epoch();
            check("the run is configured before any of this (epoch " + armed + ")",
                  armed == 1L && l.client.maySend());

            l.client.setConfigGuard(scope -> scope.containsKey("limit.rate_rps")
                    ? "limit.rate_rps cannot change mid-run: this run armed at 5"
                    : null);

            l.out.write(Frame.encode(configureFrame("e-1", 41L),
                    ("scope.include\thttps://a/*\nlimit.rate_rps\t1\n")
                            .getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded err = read(l.reader, l.peer, "the refused configure");
            check("a configure that would move an armed limit is refused, not acked (got "
                  + err.header.get("t") + ")", "error".equals(err.header.get("t")));
            check("with class bad_config (got " + err.header.get("class") + ")",
                  "bad_config".equals(err.header.get("class")));
            check("and the detail is the guard's own words",
                  String.valueOf(err.header.get("detail"))
                          .contains("cannot change mid-run"));

            waitUntil(() -> !l.client.maySend());
            check("a configure it could not act on drops to DENY-ALL", !l.client.maySend());

            // A configure the guard allows still works, and the epoch it gets
            // is the NEXT one -- not the next but one.
            l.out.write(Frame.encode(configureFrame("e-1", 42L),
                    ("scope.include\thttps://NARROW/*\n")
                            .getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded ack = read(l.reader, l.peer, "the corrected configured ack");
            check("the channel survives, so a corrected configure is heard (got "
                  + ack.header.get("t") + ")", "configured".equals(ack.header.get("t")));
            check("and the refused configure consumed NO epoch (got "
                  + ack.header.get("config_epoch") + ")",
                  Long.valueOf(armed + 1).equals(ack.header.get("config_epoch")));
            waitUntil(l.client::maySend);
            check("with the corrected scope",
                  l.client.authorisation().scope().toString().contains("NARROW"));

            // A guard that THROWS is a refusal. It is asked about an
            // operator's intent, and an answer it could not produce is not
            // permission.
            l.client.setConfigGuard(scope -> { throw new IllegalStateException("boom"); });
            l.out.write(Frame.encode(configureFrame("e-1", 43L),
                    ("scope.include\thttps://b/*\n").getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded threw = read(l.reader, l.peer, "the throwing-guard error");
            check("a guard that throws refuses rather than letting the configure through ("
                  + threw.header.get("class") + ")",
                  "error".equals(threw.header.get("t"))
                  && "bad_config".equals(threw.header.get("class")));
            check("and says so rather than escaping",
                  String.valueOf(threw.header.get("detail")).contains("boom"));

            // ...and NO guard accepts. The asymmetry with setHaltSource is
            // deliberate and setConfigGuard says why: a missing halt source
            // leaves a question about stopping unanswered, where a missing
            // config guard leaves the pre-existing silent-ignore. Failing
            // closed here would mean an extension that cannot be configured.
            l.client.setConfigGuard(null);
            l.out.write(Frame.encode(configureFrame("e-1", 44L),
                    ("scope.include\thttps://c/*\nlimit.rate_rps\t1\n")
                            .getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded none = read(l.reader, l.peer, "the unguarded configured ack");
            check("an uninstalled guard accepts (got " + none.header.get("t") + ")",
                  "configured".equals(none.header.get("t")));
        } finally {
            Files.deleteIfExists(dir.resolve("cg.sock")); Files.deleteIfExists(dir);
        }
    }

    /**
     * The kill paths that never touch this client's own flag still deny.
     *
     * BridgeClient writes its own `halted` flag in exactly two places -- the
     * `halt` and `resume` frame arms -- and spec s4 names THREE kill paths.
     * The sentinel file ("the socket is dead, stop by hand"), its stalled-
     * poller rule, and the auto-halt on target distress all reach HaltSwitch
     * or Distress and none of them reach that flag. MEASURED on a configured
     * live client before setHaltSource existed:
     *
     *   sentinel file present   HaltSwitch.halted()=true    maySend()=true
     *   poller stalled          HaltSwitch.halted()=true    maySend()=true
     *   auto-halt tripped       stopReason() non-null       maySend()=true
     *
     * and checkMaySend() threw nothing in all three. COUNTED on the reviewed
     * tree: zero calls anywhere in extension/src -- the only occurrences there
     * were the two declarations themselves -- against 53 lines of
     * extension/test, 60 occurrences of them in this file alone. So the whole
     * suite kept the pair green while it was fail-open against two thirds of
     * s4's promise, which is how it survived eight task reviews.
     *
     * WHAT THIS TEST OWNS and what it does not. The sentinel leg is driven
     * here through a REAL HaltSwitch, because that is the leg that proves
     * this client asks something other than its own flag. The auto-halt leg
     * lives in SenderTest.theHeldReasonIsTheSameAnswerTheSendPathActsOn --
     * that is where Distress is -- and the wiring that installs the real
     * authority in production is counted by ChokepointTest. The source
     * installed here is HaltSwitch::reason rather than the Sender method
     * HxExtension installs, so that this file needs no Policy, Redactor or
     * Http to say what it has to say.
     */
    static void theKillPathsThatNeverTouchTheLocalFlagStillDenySending() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltsource");
        Path sentinel = dir.resolve("halt");
        // A constant clock: unstarted the switch never reads one, and once
        // started the staleness rule reads 0 - 0, which is never stale. This
        // test is about the SENTINEL, not about time.
        HaltSwitch hs = new HaltSwitch(() -> 0L, sentinel, 500L);
        try (Live l = live(dir, "src.sock")) {
            l.client.setHaltSource(hs::reason);
            check("configured, nothing halted, and the source says so",
                  l.client.maySend());

            // The operator stops the run by hand. Nothing goes near a frame:
            // this path exists for when the bridge itself is gone.
            Files.writeString(sentinel, "stopped by hand\n");
            hs.start();
            try {
                check("the authority the send path asks is halted", hs.halted());
                check("and so is maySend(), which used to answer true here",
                      !l.client.maySend());
                String message = null;
                try { l.client.checkMaySend(); }
                catch (BridgeClient.NotConfigured e) { message = e.getMessage(); }
                check("checkMaySend throws, and says which halt (" + message + ")",
                      message != null && message.contains("halt sentinel present"));
                // The local flag is untouched throughout, and the message is
                // how that is visible: the flag's own branch answers
                // "halted: no reason given" for a client no frame has halted,
                // so a message naming the SENTINEL is proof the refusal came
                // from the source and not from a flag somebody quietly wired.
                check("...and the refusal came from the source, not the local flag ("
                      + message + ")",
                      message != null && !message.contains("no reason given"));
            } finally {
                hs.stop();
            }
        } finally {
            Files.deleteIfExists(sentinel);
            Files.deleteIfExists(dir.resolve("src.sock"));
            Files.deleteIfExists(dir);
        }

        // ---- and the two ways the source itself can fail ------------------
        //
        // Both answer DENY. A client that cannot find out whether the run is
        // stopped has not found out that it is running, which is the whole of
        // this branch.
        Path d2 = Files.createTempDirectory("hxhaltsource2");
        try (Live l = live(d2, "n.sock")) {
            // live() installs NOTHING_HELD; take it away again.
            l.client.setHaltSource(null);
            check("an uninstalled halt source denies rather than permits",
                  !l.client.maySend());
            String uninstalled = null;
            try { l.client.checkMaySend(); }
            catch (BridgeClient.NotConfigured e) { uninstalled = e.getMessage(); }
            check("and says so (" + uninstalled + ")",
                  uninstalled != null && uninstalled.contains("no halt source installed"));

            l.client.setHaltSource(() -> { throw new IllegalStateException("boom"); });
            check("a halt source that THROWS denies too", !l.client.maySend());
            String threw = null;
            try { l.client.checkMaySend(); }
            catch (BridgeClient.NotConfigured e) { threw = e.getMessage(); }
            check("and that is a refusal, not the throw escaping (" + threw + ")",
                  threw != null && threw.contains("boom"));
        } finally {
            Files.deleteIfExists(d2.resolve("n.sock"));
            Files.deleteIfExists(d2);
        }
    }

    /**
     * A `halt` frame carrying no `reason` key must not deliver the WORD
     * "null".
     *
     * `String.valueOf(f.header.get("reason"))` answers the four-character
     * string "null" for an absent key, and "null" is neither null nor blank,
     * so HaltSwitch's "halted by frame, no reason given" fallback could never
     * fire for a bridge-delivered halt -- the only production caller. Measured
     * end to end, through a real socket: reason() was the literal "null" and
     * checkMaySend() threw `NotConfigured: halted: null`. Both places an
     * operator reads showed them the word null where the reason belongs.
     */
    static void aHaltFrameWithNoReasonDoesNotDeliverTheWordNull() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltnoreasonframe");
        HaltSwitch hs = new HaltSwitch(() -> 0L, dir.resolve("halt"), 500L);
        try (Live l = live(dir, "hn.sock")) {
            l.client.setHaltSink(new BridgeClient.HaltSink() {
                public void halted(String reason) { hs.haltedByFrame(reason); }
                public void resumed()             { hs.resumedByFrame(); }
            });

            l.out.write(Frame.encode(Map.of("v", 1L, "t", "halt"), new byte[0]));
            l.out.flush();
            waitUntil(hs::halted);
            check("a halt frame with no reason still halts the send path", hs.halted());
            check("and the switch's own fallback is what the send path reports ("
                  + hs.reason() + ")",
                  "halted by frame, no reason given".equals(hs.reason()));

            String message = "";
            try { l.client.checkMaySend(); } catch (BridgeClient.NotConfigured e) { message = e.getMessage(); }
            check("and the client's refusal does not read `halted: null` (" + message + ")",
                  message.startsWith("halted:") && !message.contains("null"));
        } finally {
            Files.deleteIfExists(dir.resolve("hn.sock")); Files.deleteIfExists(dir);
        }
    }

    /** A halt that could not be delivered is an unknown state, and unknown is
     *  stop. Not "log it and carry on": the frame that was meant to stop
     *  issuance went nowhere. */
    static void aHaltSinkThatThrowsDropsToDenyAll() throws Exception {
        Path dir = Files.createTempDirectory("hxhaltsinkthrows");
        try (Live l = live(dir, "ht.sock")) {
            l.client.setHaltSink(new BridgeClient.HaltSink() {
                public void halted(String reason) { throw new IllegalStateException("switch is gone"); }
                public void resumed()             { }
            });
            check("configured before the undeliverable halt", l.client.maySend());

            l.out.write(Frame.encode(
                    Map.of("v", 1L, "t", "halt", "reason", "operator pressed stop"), new byte[0]));
            l.out.flush();
            waitUntil(() -> !l.client.isConfigured());
            // isConfigured(), not maySend(): the local halt flag would answer
            // maySend() false on its own, so a client that had merely logged
            // the failure and carried on under the standing scope would pass a
            // maySend() check. DENY-ALL means the scope went too.
            check("a halt that could not be delivered drops to DENY-ALL",
                  !l.client.isConfigured());
            check("and the transition is logged", l.log.sawError("halt sink threw, deny-all"));
        } finally {
            Files.deleteIfExists(dir.resolve("ht.sock")); Files.deleteIfExists(dir);
        }
    }

    static Map<String, Object> sendFrame(String engagement, long id) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("v", 1L); s.put("t", "send"); s.put("id", id);
        s.put("deadline_us", System.currentTimeMillis() * 1000L + 30_000_000L);
        s.put("engagement_id", engagement);
        s.put("identity_id", null);
        s.put("target_host", "app.example.test");
        s.put("target_port", 443L);
        s.put("tls", true);
        return s;
    }

    static final byte[] GET = ("GET /api/orders HTTP/1.1\r\nHost: app.example.test\r\n\r\n")
            .getBytes(StandardCharsets.UTF_8);

    /** The send arm reads the Authorisation ONCE and hands the whole snapshot
     *  down. This is the only place in the extension that reads it at all. */
    static void theSendArmHandsTheHandlerOneCoherentAuthorisation() throws Exception {
        Path dir = Files.createTempDirectory("hxsendarm");
        try (Live l = live(dir, "s.sock")) {
            final List<BridgeClient.Authorisation> seen = new ArrayList<>();
            l.client.setSendHandler((h, b, auth) -> {
                seen.add(auth);
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("v", 1L); r.put("t", "result"); r.put("id", h.get("id"));
                r.put("status", 200L); r.put("outcome", "ok");
                r.put(BridgeClient.BODY_KEY,
                      "HTTP/1.1 200 OK\r\n\r\nhi".getBytes(StandardCharsets.UTF_8));
                return r;
            });

            l.out.write(Frame.encode(sendFrame("e-1", 11L), GET));
            l.out.flush();
            // Through this class's deadline wrapper, not a bare reader.read():
            // a send arm that answers nothing parks here forever, and a class
            // that prints no summary line reads as zero failures.
            Frame.Decoded result = read(l.reader, l.peer, "the result frame");

            check("the send arm answers with the handler's frame",
                  "result".equals(result.header.get("t")));
            check("the handler saw the request body",
                  Long.valueOf(11L).equals(result.header.get("id")));
            check("the reserved body key never reaches the wire",
                  !result.header.containsKey(BridgeClient.BODY_KEY));
            check("and its bytes became the frame body",
                  "HTTP/1.1 200 OK\r\n\r\nhi".equals(
                          new String(result.body, StandardCharsets.UTF_8)));
            check("the handler was given exactly one Authorisation", seen.size() == 1);
            check("with the acked epoch", seen.get(0).epoch() == 1L);
            check("and the scope that epoch authorised",
                  seen.get(0).scope().toString().contains("WIDE"));
        } finally {
            Files.deleteIfExists(dir.resolve("s.sock")); Files.deleteIfExists(dir);
        }
    }

    /** s6: every send carries engagement_id and the extension refuses a
     *  mismatch -- before the handler, which would otherwise decide about a
     *  request belonging to somebody else's engagement. */
    static void aSendForAnotherEngagementNeverReachesTheHandler() throws Exception {
        Path dir = Files.createTempDirectory("hxsendmismatch");
        try (Live l = live(dir, "m.sock")) {
            final int[] calls = {0};
            l.client.setSendHandler((h, b, auth) -> { calls[0]++; return new LinkedHashMap<>(); });

            l.out.write(Frame.encode(sendFrame("SOMEONE-ELSE", 12L), GET));
            l.out.flush();
            Frame.Decoded err = read(l.reader, l.peer, "the engagement-mismatch error");

            check("a send for another engagement is answered with an error",
                  "error".equals(err.header.get("t")));
            check("the class names the mismatch",
                  "engagement_mismatch".equals(err.header.get("class")));
            check("and the handler was never called (" + calls[0] + ")", calls[0] == 0);
            check("the connection survives a mismatched send", l.client.maySend());

            // A frame with NO engagement_id at all, which is a different input
            // from a frame naming somebody else's. MEASURED before this block
            // existed: teaching the check to skip an ABSENT key -- the shape a
            // "tolerate an optional field" change produces -- left the whole
            // Java suite at 9 x ALL PASS / 1407 ok / 0 FAIL, because every
            // test here supplied the key.
            //
            // `engagementId.equals(null)` is false, so absent already refuses.
            // That is the fail-closed direction and it is worth an input:
            // s6 says EVERY send carries it, so a frame without one is not
            // speaking this protocol and cannot be decided about at all.
            Map<String, Object> noEngagement = sendFrame("e-1", 14L);
            noEngagement.remove("engagement_id");
            l.out.write(Frame.encode(noEngagement, GET));
            l.out.flush();
            Frame.Decoded absent = read(l.reader, l.peer, "the absent-engagement error");

            check("a send with NO engagement_id is answered with an error",
                  "error".equals(absent.header.get("t")));
            check("the class names the mismatch for an absent id too (got "
                  + absent.header.get("class") + ")",
                  "engagement_mismatch".equals(absent.header.get("class")));
            check("and the handler was still never called (" + calls[0] + ")", calls[0] == 0);
            check("the connection survives that too", l.client.maySend());
        } finally {
            Files.deleteIfExists(dir.resolve("m.sock")); Files.deleteIfExists(dir);
        }
    }

    /** An exception is never an implicit allow. A handler that throws is
     *  answered, then the client drops to DENY-ALL and closes. */
    static void aSendHandlerThatThrowsDropsToDenyAll() throws Exception {
        Path dir = Files.createTempDirectory("hxsendthrow");
        try (Live l = live(dir, "t.sock")) {
            check("live before the throw", l.client.maySend());
            l.client.setSendHandler((h, b, auth) -> {
                throw new IllegalStateException("policy table was null");
            });

            l.out.write(Frame.encode(sendFrame("e-1", 13L), GET));
            l.out.flush();
            Frame.Decoded err = read(l.reader, l.peer, "the internal-failure error");

            check("a throwing handler still answers the caller",
                  "error".equals(err.header.get("t")));
            check("with a class rather than a silent bridge_lost",
                  "not_configured".equals(err.header.get("class")));
            check("and the detail names the failure",
                  String.valueOf(err.header.get("detail")).contains("policy table was null"));
            // The class is OVERLOADED: `not_configured` is also what an
            // operator who has not configured gets, and records.DENIAL_KIND
            // files both under kind='not_configured'. So a store query
            // grouping by kind reads a crashed send path as an unauthorised
            // run unless the DETAIL says otherwise, in a form a consumer can
            // test for rather than parse prose out of.
            check("and it is marked as the EXTENSION's fault, not the operator's ("
                  + err.header.get("detail") + ")",
                  String.valueOf(err.header.get("detail"))
                          .startsWith(BridgeClient.EXTENSION_FAULT));

            waitUntil(() -> !l.client.maySend());
            check("a send path that threw drops to DENY-ALL", !l.client.maySend());
            check("and the transition is logged",
                  l.log.sawError("send handler threw"));
        } finally {
            Files.deleteIfExists(dir.resolve("t.sock")); Files.deleteIfExists(dir);
        }
    }

    /** No handler is a state, not an exemption. */
    static void aSendWithNoHandlerInstalledIsRefused() throws Exception {
        Path dir = Files.createTempDirectory("hxnohandler");
        try (Live l = live(dir, "n.sock")) {
            l.out.write(Frame.encode(sendFrame("e-1", 14L), GET));
            l.out.flush();
            Frame.Decoded err = read(l.reader, l.peer, "the no-handler error");
            check("a send with no handler is refused",
                  "error".equals(err.header.get("t"))
                  && "not_configured".equals(err.header.get("class")));
            check("and marked as the extension's fault rather than the operator's ("
                  + err.header.get("detail") + ")",
                  String.valueOf(err.header.get("detail"))
                          .startsWith(BridgeClient.EXTENSION_FAULT));

            // The input that separates the guard from its absence, and the
            // class alone is not it: delete the null check and h.handle()
            // NPEs, the send arm's catch answers the SAME not_configured
            // class, and the two are indistinguishable from the error frame --
            // measured green across all nine classes. What differs is what
            // happens next. The catch drops to DENY-ALL and closes; the guard
            // refuses one send and leaves a live client that a handler can
            // still be installed on, which is what "a state, not an exemption"
            // means.
            l.client.setSendHandler((h, b, auth) -> {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("v", 1L); r.put("t", "result"); r.put("id", h.get("id"));
                r.put("status", 200L); r.put("outcome", "ok");
                return r;
            });
            l.out.write(Frame.encode(sendFrame("e-1", 15L), GET));
            l.out.flush();
            Frame.Decoded then = read(l.reader, l.peer, "the result once a handler is installed");
            check("a missing handler is not a bridge failure: the client is still live",
                  l.client.maySend());
            check("and the handler installed afterwards answers",
                  "result".equals(then.header.get("t"))
                  && Long.valueOf(15L).equals(then.header.get("id")));
        } finally {
            Files.deleteIfExists(dir.resolve("n.sock")); Files.deleteIfExists(dir);
        }
    }

    /**
     * The send arm's catch does TWO things -- `denyAll()` and `return false` --
     * and each was masking the other.
     *
     * Delete `denyAll()` and the read loop's own finally still lands in
     * DENY-ALL on the way out, so `maySend()` reads false either way. Delete
     * `return false` and `denyAll()` has already cleared `configured`, so
     * `maySend()` reads false again. Both mutations were measured at 9 x ALL
     * PASS, and the pair is not redundant at all: the finally only runs
     * because the arm asked the loop to leave, and the loop only leaves a
     * client that is already denying because the arm denied first.
     *
     * handle() is called DIRECTLY here, which is what separates them. Nothing
     * unwinds the read loop, so denyAll()'s absence is visible in maySend(),
     * and the return value is visible on its own -- the answer to "does the
     * control channel go on serving a send path that just threw", which spec
     * s4 answers no.
     */
    static void aThrowingSendArmBothDeniesAndStopsTheLoop() throws Exception {
        Path dir = Files.createTempDirectory("hxsendarmthrow");
        try (Live l = live(dir, "at.sock")) {
            check("live before the throw", l.client.maySend());
            l.client.setSendHandler((h, b, auth) -> {
                throw new IllegalStateException("the redactor is gone");
            });

            boolean keepReading = l.client.handle(
                    Frame.decode(Frame.encode(sendFrame("e-1", 21L), GET)));
            Frame.Decoded err = read(l.reader, l.peer, "the internal-failure error");
            check("the caller is answered with a class, not a silent bridge_lost",
                  "error".equals(err.header.get("t"))
                  && "not_configured".equals(err.header.get("class")));
            // Each of the two, separately.
            check("the arm itself drops to DENY-ALL rather than leaving it to the "
                  + "read loop's finally", !l.client.maySend());
            check("and it tells the read loop to stop (" + keepReading + ")", !keepReading);
        } finally {
            Files.deleteIfExists(dir.resolve("at.sock")); Files.deleteIfExists(dir);
        }
    }

    /**
     * A limit the extension cannot use is refused WHEN IT ARRIVES, and the
     * control channel survives the refusal.
     *
     * REPRODUCED end to end before this existed, over a real unix socket:
     *
     *     configure ack: t=configured  epoch=1     <- the operator is told OK
     *     first send:    t=error class=not_configured
     *                    detail=... limit.rate_rps is not an integer: as fast
     *                    as possible
     *     after it:      maySend()=false, http calls=0
     *     a corrected configure: IMPOSSIBLE -- java.io.IOException: Broken pipe
     *
     * Fail-closed, and the detail even named the cause -- but the answer came
     * one frame too late and on the wrong side of a channel close. HxExtension
     * dials once, on a daemon thread, and has no reconnect, so recovery meant
     * reloading the extension inside Burp.
     *
     * bad_config is the answer that already existed for exactly this shape: an
     * operator's configure that we could not act on. It drops to DENY-ALL --
     * identical safety, nothing is issued either way -- and keeps the channel,
     * so the corrected configure below is heard. The asymmetry with an equally
     * malformed value arriving one frame later was the whole argument.
     */
    static void anUnusableLimitIsRefusedAtConfigureTimeAndTheChannelSurvives()
            throws Exception {
        Path dir = Files.createTempDirectory("hxbadlimit");
        try (Live l = live(dir, "bl.sock")) {
            check("wide scope is in force first",
                  l.client.authorisation().scope().toString().contains("WIDE"));

            l.out.write(Frame.encode(configureFrame("e-1", 31L),
                    ("scope.include\thttps://a/*\n"
                     + "limit.rate_rps\tas fast as possible\n")
                            .getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded err = read(l.reader, l.peer, "the bad-limit error");
            check("an unusable limit is answered at CONFIGURE time (got "
                  + err.header.get("t") + ")", "error".equals(err.header.get("t")));
            check("with class bad_config (got " + err.header.get("class") + "), not an "
                  + "ack the first send has to take back",
                  "bad_config".equals(err.header.get("class")));
            check("and the detail names the key and the value it could not read",
                  String.valueOf(err.header.get("detail")).contains("limit.rate_rps")
                  && String.valueOf(err.header.get("detail")).contains("as fast as possible"));

            waitUntil(() -> !l.client.maySend());
            check("a configure it could not act on drops to DENY-ALL", !l.client.maySend());
            check("the superseded wider scope is dropped",
                  l.client.authorisation().scope().isEmpty());

            // The half that the send-time refusal could not deliver.
            l.out.write(Frame.encode(configureFrame("e-1", 32L),
                    ("scope.include\thttps://NARROW/*\nlimit.rate_rps\t3\n")
                            .getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded ack = read(l.reader, l.peer, "the corrected configured ack");
            check("the channel survives, so a corrected configure is heard (got "
                  + ack.header.get("t") + ")", "configured".equals(ack.header.get("t")));
            waitUntil(l.client::maySend);
            check("and the run is live again under the corrected config",
                  l.client.maySend());
            check("with the corrected scope",
                  l.client.authorisation().scope().toString().contains("NARROW"));

            // Two answers to "how fast" is not a limit either, and it lands in
            // the same place rather than at the first send.
            l.out.write(Frame.encode(configureFrame("e-1", 33L),
                    ("scope.include\thttps://a/*\nlimit.max_requests\t10\n"
                     + "limit.max_requests\t2000\n").getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded twice = read(l.reader, l.peer, "the repeated-limit error");
            check("a repeated limit key is bad_config too (got "
                  + twice.header.get("class") + ")",
                  "bad_config".equals(twice.header.get("class")));

            // ZERO is the third branch, and the only one of the three that was
            // unpinned: `limit.rate_rps 0` is a perfectly good integer set
            // exactly once, so neither refusal above sees it. Deleting
            // `if (n <= 0) throw ...` from ConfigBody.positiveInteger left
            // 9 x ALL PASS / 1364 ok / 0 FAIL -- and positiveInteger's own
            // javadoc invites the deletion by noting that Limits.positive
            // still makes the same three checks, from which a reader concludes
            // the line is redundant.
            //
            // What it restores is not a tidiness regression. 0 parses, is
            // acked `configured`, and then throws out of Limits.arm at the
            // FIRST send -- which answers not_configured, drops to DENY-ALL
            // and CLOSES the channel, with no reconnect in HxExtension. That
            // is precisely the unrecoverable failure the rest of this method
            // was written to close, restored invisibly.
            l.out.write(Frame.encode(configureFrame("e-1", 34L),
                    ("scope.include\thttps://a/*\nlimit.rate_rps\t0\n")
                            .getBytes(StandardCharsets.UTF_8)));
            l.out.flush();
            Frame.Decoded zero = read(l.reader, l.peer, "the zero-limit error");
            check("a limit of ZERO is refused at configure time, not at the first "
                  + "send (got " + zero.header.get("t") + "/"
                  + zero.header.get("class") + ")",
                  "bad_config".equals(zero.header.get("class")));
        } finally {
            Files.deleteIfExists(dir.resolve("bl.sock")); Files.deleteIfExists(dir);
        }
    }

    /**
     * The capture sink, on the wire: one frame, two bodies, version stamped.
     *
     * The two halves cannot share one opaque body -- the far side
     * content-addresses each on its own -- and a `v` this side forgets is a
     * frame BridgeServer._handle drops before it looks at `t` at all.
     */
    static void theExchangeSinkFramesBothHalves() throws Exception {
        Path dir = Files.createTempDirectory("hxbridge-x");
        try (Live l = live(dir, "xs.sock")) {
            BridgeClient.ExchangeSink sink = l.client.exchangeSink();
            Map<String, Object> h = new LinkedHashMap<>();
            h.put("t", "exchange");
            h.put("via", "proxy");
            h.put("source", "operator");
            h.put("url", "http://app.test/x");
            check("a delivered exchange answers TRUE, which is what lets the "
                  + "drain not count it as a drop",
                  sink.exchange(h, "REQ".getBytes(StandardCharsets.UTF_8),
                                "RESPONSE".getBytes(StandardCharsets.UTF_8)));
            Frame.Decoded f = read(l.reader, l.peer, "the exchange frame");
            check("the frame is an exchange (" + f.header.get("t") + ")",
                  "exchange".equals(f.header.get("t")));
            check("and carries the protocol version (" + f.header.get("v") + ")",
                  Long.valueOf(BridgeClient.PROTOCOL_VERSION).equals(f.header.get("v")));
            check("and declares two bodies (" + f.header.get(Frame.BODIES_KEY) + ")",
                  Long.valueOf(2L).equals(f.header.get(Frame.BODIES_KEY)));
            check("the request half arrived intact ("
                  + new String(f.body, StandardCharsets.UTF_8) + ")",
                  "REQ".equals(new String(f.body, StandardCharsets.UTF_8)));
            check("and the response half separately, not spliced onto it ("
                  + (f.second == null ? "null"
                     : new String(f.second, StandardCharsets.UTF_8)) + ")",
                  f.second != null
                  && "RESPONSE".equals(new String(f.second, StandardCharsets.UTF_8)));

            // A drop report the far side can add to run.dropped_total.
            check("a delivered drop report answers TRUE, which is what lets "
                  + "the drain advance its cumulative counter",
                  sink.dropped(4L, "crawler"));
            Frame.Decoded d = read(l.reader, l.peer, "the drop report");
            check("the drop frame is the type hx.capture knows ("
                  + d.header.get("t") + ")", "dropped".equals(d.header.get("t")));
            check("and carries n as an integer (" + d.header.get("n") + ")",
                  Long.valueOf(4L).equals(d.header.get("n")));
            check("and names the source whose run it belongs to ("
                  + d.header.get("source") + ")",
                  "crawler".equals(d.header.get("source")));

            // A source with no spelling gets no key, rather than the operator's.
            // hx/capture.py documents what an ABSENT source means and answers
            // the operator's run for it; a second place writing "operator" is a
            // second place that decision can drift. NULL is how "no spelling"
            // reaches here now: `Capture.sourceName` answers it for a Source
            // this side has no string for, and this file no longer knows what
            // an hx.proxy enum is at all.
            sink.dropped(1L, null);
            Frame.Decoded u = read(l.reader, l.peer, "the unattributed drop report");
            check("an unspellable source is omitted, not defaulted ("
                  + u.header.get("source") + ")",
                  !u.header.containsKey("source"));

            // A denial: S4's second enforcement point refusing a request.
            // ONE body slot and it is empty -- the request never left, so
            // there are no bytes to carry, and `server.py::_capture` splits
            // two bodies out of an `exchange` frame ONLY. A denial framed
            // with two would be read as a malformed exchange by the far side
            // and counted as a drop rather than recorded as the refusal it is.
            Map<String, Object> dn = new LinkedHashMap<>();
            dn.put("t", "denial");
            dn.put("via", "proxy");
            dn.put("source", "operator");
            dn.put("method", "POST");
            dn.put("url", "http://app.test/account/delete");
            dn.put("error_class", "dangerous_denied");
            dn.put("detail", "matches dangerous.path /account/delete");
            check("a delivered denial answers TRUE, which is what lets the "
                  + "drain not count it as a drop", sink.denial(dn));
            Frame.Decoded n = read(l.reader, l.peer, "the denial frame");
            check("the denial frame is the type hx.capture knows ("
                  + n.header.get("t") + ")", "denial".equals(n.header.get("t")));
            check("and carries the protocol version (" + n.header.get("v") + ")",
                  Long.valueOf(BridgeClient.PROTOCOL_VERSION).equals(n.header.get("v")));
            check("and the class the far side routes on ("
                  + n.header.get("error_class") + ")",
                  "dangerous_denied".equals(n.header.get("error_class")));
            check("and declares ONE body, not two (" + n.header.get(Frame.BODIES_KEY)
                  + ")", !n.header.containsKey(Frame.BODIES_KEY));
            check("which is empty (" + n.body.length + " bytes)",
                  n.body.length == 0 && n.second == null);
        } finally {
            Files.deleteIfExists(dir.resolve("xs.sock")); Files.deleteIfExists(dir);
        }
    }

    /**
     * A dead socket loses the records. It must not ALSO stop the browser, and
     * it must not read as success.
     *
     * Not raising is the same rule as "offering never blocks", one layer down:
     * an exception out of here lands on Capture's drain thread, and the drain
     * dying is how a lost record becomes a permanently silent capture. So
     * every arm of the sink swallows.
     *
     * SWALLOWING IS NOT ENOUGH, and this method's last check used to say it
     * was: "and so was the lost drop report, which is the coverage floor",
     * about a line in Burp's log. It is not the coverage floor.
     * `run.dropped_total` is, and nothing reads Burp's log into it. Because
     * these methods returned normally after logging, the drain read a failed
     * write as an acknowledged report and advanced its cumulative counter past
     * it: 5,000 drops counted while the harness restarts, one log line, a
     * reconnect, and `run.dropped_total = 0`. The boolean is what the far side
     * can act on.
     */
    static void theExchangeSinkNeverRaisesIntoCapture() throws Exception {
        Path dir = Files.createTempDirectory("hxbridge-xd");
        try (Live l = live(dir, "xd.sock")) {
            BridgeClient.ExchangeSink sink = l.client.exchangeSink();
            l.peer.close();
            l.client.close();          // the channel is gone; writes must fail
            boolean threw = false;
            boolean anyClaimedDelivery = false;
            try {
                for (int i = 0; i < 5; i++) {
                    anyClaimedDelivery |=
                        sink.exchange(Map.of("t", "exchange", "url", "http://a/" + i),
                                      "r".getBytes(StandardCharsets.UTF_8),
                                      "s".getBytes(StandardCharsets.UTF_8));
                    anyClaimedDelivery |= sink.dropped(1L, "operator");
                    anyClaimedDelivery |=
                        sink.denial(Map.of("t", "denial", "url", "http://a/" + i,
                                           "error_class", "scope_denied"));
                }
            } catch (Throwable t) { threw = true; }
            check("no arm raised into the drain thread", !threw);
            check("and none claimed to have delivered anything, which is "
                  + "what keeps the coverage floor countable",
                  !anyClaimedDelivery);
            check("the lost exchange was logged, not swallowed silently",
                  l.log.sawError("exchange frame undeliverable"));
            check("and so was the lost drop report",
                  l.log.sawError("drop report undeliverable"));
            // The denial is the newest of the three and the easiest to leave
            // out: a refusal hx recorded nowhere is the one loss that reads,
            // from the operator's side, exactly like a request that was
            // allowed.
            check("and so was the lost denial",
                  l.log.sawError("denial frame undeliverable"));
        } finally {
            Files.deleteIfExists(dir.resolve("xd.sock")); Files.deleteIfExists(dir);
        }
    }

    static final byte[] CFG =
            "scope.include\thttps://RACE/*\n".getBytes(StandardCharsets.UTF_8);

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

    /**
     * What a `not_configured` detail says when the extension is at fault
     * rather than the operator.
     *
     * `not_configured` is OVERLOADED: it is the class for "no configure has
     * been acknowledged" AND for a send path that threw or was never
     * installed. docs/bridge-protocol.md's class list records that;
     * spec s6's does not -- it names the class and nothing more, and widening
     * s6's own enumeration was not this round's licence.
     * The two readings are opposite instructions. The first says an operator
     * has not authorised the run yet and the second says this jar is broken,
     * and only the second is a reason to look at a stack trace.
     *
     * That matters at the store, not just at the console. `records.DENIAL_KIND`
     * maps this class to `kind='not_configured'`, so both file the same row
     * and `SELECT kind, COUNT(*) FROM denial GROUP BY kind` reads a crash as
     * an unauthorised run. The class cannot be split without amending s6's
     * enumeration, which is a protocol change; the DETAIL can carry it today,
     * and a prefix carries it in a form a consumer can test for rather than
     * one it has to parse prose out of. `records.EXTENSION_FAULT` is the same
     * string on the Python side.
     */
    public static final String EXTENSION_FAULT = "extension fault: ";

    public static class NotConfigured extends RuntimeException {
        public NotConfigured(String m) { super(m); }
    }

    /**
     * The two logging calls the bridge makes. Montoya's Logging satisfies it
     * through an adapter and the test fake implements it directly. Declaring
     * it here is what keeps BridgeClient free of a compile-time Montoya
     * dependency -- and unlike the `Object log` it replaces, it can actually
     * be called.
     */
    public interface Log {
        void info(String s);
        void error(String s);
    }

    /** The reserved key a SendHandler puts the redacted response body under.
     *  It cannot travel in a flat JSON header, and Json.write refuses a byte[]
     *  -- so a framer that forgets the remove() below throws JsonError rather
     *  than quietly writing a result frame with the evidence missing. */
    public static final String BODY_KEY = "@body";

    /**
     * What answers a `send` frame. Sender.issue has this shape; it is a
     * functional interface so HxExtension can install it as a lambda, which
     * keeps hx.send.Sender free of any declared dependency on this class
     * beyond the Authorisation record it is handed.
     */
    @FunctionalInterface
    public interface SendHandler {
        Map<String, Object> handle(Map<String, Object> header, byte[] body, Authorisation auth);
    }

    // Written on Burp's initialize thread before connect(), read on the read
    // loop's thread. Volatile for the same reason every other field here is.
    private volatile SendHandler sendHandler;

    /** Install the send path. Called before connect(): a client that is live
     *  with no handler answers every send `not_configured`, which is correct
     *  but useless. */
    public void setSendHandler(SendHandler h) { this.sendHandler = h; }

    /**
     * The unsolicited stop frame, burp -> py.
     *
     * Spec s6: auto-halt is extension-initiated, so there is no outstanding id
     * to answer. This is a push, not a reply, and it is the only way the
     * harness learns of a stop before the next send fails -- which matters
     * because `run.status = 'aborted'` needs a stop_reason, and the only place
     * that reason exists is the extension that decided to stop.
     */
    public interface HaltNotifier {
        void halted(String reason, String host, String window);
    }

    /**
     * A notifier that frames {v, t:"halted", reason, host, window} and writes
     * it down the socket.
     *
     * The three fields are what the harness needs to write one row: the
     * reason, the host that produced it, and the window it was measured over
     * -- "5xx rate 0.40" is not an explanation without the last of those.
     */
    public HaltNotifier haltNotifier() {
        return (reason, host, window) -> {
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("v", PROTOCOL_VERSION);
            f.put("t", "halted");
            f.put("reason", reason);
            f.put("host", host);
            f.put("window", window);
            try {
                send(f, new byte[0]);
            } catch (IOException e) {
                // The stop could not be delivered, so nothing on the far side
                // will record it. A peer that cannot be told we stopped is a
                // peer we have no authorisation from either: DENY-ALL is where
                // an undelivered stop lands.
                log.error("hx: halted frame undeliverable, deny-all: " + e);
                denyAll();
            }
        };
    }

    /**
     * Where `halt` and `resume` frames land: the switch the SEND PATH asks.
     *
     * HaltSwitch has the matching pair of methods but does not implement this
     * interface -- hx.send must not take a compile-time dependency on the
     * bridge for a two-method callback -- so HxExtension installs a delegating
     * instance, in one place, before it dials.
     */
    public interface HaltSink {
        void halted(String reason);
        void resumed();
    }

    // Written on Burp's initialize thread before connect(), read on the read
    // loop's thread. Volatile for the same reason every other field here is.
    private volatile HaltSink haltSink;

    /** Install the halt switch. Called before connect(): a client that goes
     *  live with no sink routes halt frames to its own flag alone, and that
     *  flag is not what Sender asks. */
    public void setHaltSink(HaltSink s) { this.haltSink = s; }

    /**
     * The other direction: what the SEND PATH would refuse for, asked.
     *
     * {@link HaltSink} is one-way, and that asymmetry was a fail-open hole.
     * This client keeps a {@code halted} flag written by the `halt` and
     * `resume` frame arms and by nothing else -- there are exactly TWO writes
     * to it in this file, one in each arm -- while spec s4 names THREE kill
     * paths. The sentinel file (with its stalled-poller rule) and the
     * auto-halt on target distress never reach that flag; the send path asks
     * {@code Sender.issuanceHeldReason()} instead.
     *
     * MEASURED against this client before this interface existed, with the
     * client configured and live:
     *
     *   sentinel file present   HaltSwitch.halted()=true   maySend()=true
     *   poller stalled          HaltSwitch.halted()=true   maySend()=true
     *   auto-halt tripped       stopReason() non-null      maySend()=true
     *
     * and {@link #checkMaySend()} threw nothing in all three. So a second
     * enforcement point written against the obvious gate on the class the
     * bridge already routes through -- {@code if (client.maySend())} -- would
     * keep issuing through an operator halt raised by hand.
     *
     * ONE method, and it returns the REASON rather than a boolean, so the
     * implementation HxExtension installs is {@code sender::issuanceHeldReason}
     * -- the same code the send path runs, not a second opinion assembled here
     * from the same two objects.
     */
    public interface HaltSource {
        /** Why issuance is held, or null while nothing is holding it. */
        String heldReason();
    }

    // Written on Burp's initialize thread before connect(), read wherever
    // maySend() is. Volatile for the same reason haltSink is.
    private volatile HaltSource haltSource;

    /** Install the send path's halt authority. Called before connect(), for
     *  the same reason setHaltSink is: until it is installed, maySend()
     *  answers false -- a client that cannot ask whether the run is stopped
     *  does not get to say it is not. */
    public void setHaltSource(HaltSource s) { this.haltSource = s; }

    /**
     * Where an `identity` frame's contents go: the registry the send path
     * injects from.
     *
     * DECLARED HERE, for {@link SendHandler}'s and {@link HaltSink}'s reason.
     * The registry lives in hx.send, hx.send already imports this class, and a
     * type from hx.send named here would close that into a cycle -- which
     * javac does not mind, because it sees every source at once, and which a
     * reader trying to work out which of two files is the authority on a
     * refusal does. So the bridge names a callback of its own and HxExtension,
     * the file that already knows about both packages, wires the registry to
     * it.
     *
     * The five parameters are the frame's, not the registry's: this interface
     * is what the WIRE carries, and an implementation is free to hold it
     * however it likes.
     */
    public interface IdentitySink {
        /**
         * Register or refresh one identity.
         *
         * @throws StaleIdentity the generation does not advance the one
         *   already held. Answered `stale_generation`.
         * @throws IllegalArgumentException the frame cannot be registered as
         *   it stands. Answered `bad_identity`.
         */
        void register(String identityId, int generation, String header, String value,
                      List<String> origins);
    }

    /**
     * What an {@link IdentitySink} raises for a generation that goes backwards.
     *
     * Declared in the package that has to answer `stale_generation` on the
     * wire, rather than caught by its own type from hx.send, for the reason
     * IdentitySink itself is declared here. HxExtension's sink translates
     * `IdentityRegistry.StaleGeneration` into this one, which is the only
     * place the two vocabularies meet.
     *
     * A REFUSAL AND NOT A FAULT. A replayed or reordered frame carrying an
     * older generation is exactly what the registry's monotonic rule exists to
     * refuse, so the channel survives it: one frame is answered `error`, and
     * the run goes on under the identity it already holds.
     */
    public static final class StaleIdentity extends RuntimeException {
        public StaleIdentity(String m) { super(m); }
    }

    // Written on Burp's initialize thread before connect(), read on the read
    // loop's thread. Volatile for the same reason every other field here is.
    private volatile IdentitySink identitySink;

    /** Install the identity registry. Called before connect(): until it is
     *  installed every `identity` frame is refused, which is the right answer
     *  -- a credential the send path could not have been given must not be
     *  acknowledged as registered. */
    public void setIdentitySink(IdentitySink s) { this.identitySink = s; }

    /**
     * Whether a `configure` can be acted on, asked before it is committed.
     *
     * There is exactly one thing this answers today and spec s4 names it:
     * `Limits` takes the rate and budget from the FIRST authorisation with an
     * epoch and holds them for the run, because the budget must be monotonic
     * -- a scope push must not resupply a run that has spent its requests. So
     * an operator pushing `limit.rate_rps: 1` mid-run got a fresh
     * `config_epoch`, no error, no log line, and the OLD RATE. Lowering a rate
     * is the one change that is always safe, and believing you have slowed a
     * run down when you have not is the failure to avoid.
     *
     * A refusal here is `bad_config`: DENY-ALL first, channel kept, so a
     * corrected configure can follow. Same answer as an unparseable configure
     * and for the same reason -- carrying on under the PREVIOUS intent is
     * exactly the harm when the new intent was tighter.
     *
     * This is NOT re-arming, which is a later plan's work. It is the refusal
     * that makes the absence of re-arming visible.
     */
    public interface ConfigGuard {
        /** Why this configure cannot be acted on, or null when it can. */
        String refuse(Map<String, List<String>> scope);
    }

    private volatile ConfigGuard configGuard;

    /**
     * Install it. Called before connect(), with the others.
     *
     * An UNINSTALLED guard accepts, unlike {@link #setHaltSource}, and the
     * asymmetry is deliberate: a halt source that is missing leaves a question
     * about stopping unanswered, where a config guard that is missing leaves
     * the pre-existing silent-ignore. Failing closed here would mean an
     * extension that cannot be configured at all, which is worse than the
     * thing being fixed. ChokepointTest counts the wire instead -- and as of
     * 2026-08-24 it counts it in CODE rather than raw text, which is the
     * condition this default was accepted on. While that count read comments,
     * `//c.setConfigGuard(...)` in HxExtension kept it at 1 and this guard's
     * fail-open default meant the silent-ignore came back with the whole
     * branch green: the weakest default and the weakest binding on the same
     * seam. The default is fine BECAUSE the binding is not.
     *
     * A guard that THROWS is a refusal. It is asked about an operator's
     * intent, and an answer it could not produce is not permission.
     */
    public void setConfigGuard(ConfigGuard g) { this.configGuard = g; }

    private final Path socketPath;
    private final String engagementId;
    private final String instanceId;
    private final Log log;

    private volatile SocketChannel channel;
    private volatile InputStream in;
    private volatile OutputStream out;

    // F1: close() must be STICKY. Without it a client that was closed before
    // its dial completed goes on to hello, configure and live sending -- an
    // unloaded extension holding a control channel on a daemon thread.
    private volatile boolean closed = false;

    // close() and the read loop's configure commit both mutate the permission
    // state from different threads. Re-checking `closed` after the commit only
    // makes the window narrow (~ns); this monitor makes it not exist. In a
    // component whose whole job is refusing to send, "too small to observe" is
    // not the same as "cannot happen".
    //
    // Package-private, not private: BridgeClientTest.theCommitIsExclusiveWith-
    // Close() takes this monitor itself to park a commit inside handle()'s
    // `synchronized (commitLock)` deterministically. See the note on handle()
    // below -- this field's visibility is load-bearing for that test.
    final Object commitLock = new Object();

    private final AtomicBoolean configured = new AtomicBoolean(false);
    private final AtomicBoolean halted = new AtomicBoolean(false);

    /**
     * The epoch and the scope it authorises, published together.
     *
     * They were two volatile fields, and a caller holding no lock cannot read
     * two volatiles coherently no matter where the writes sit: the review
     * measured maySend() answering true with configEpoch()==1 while
     * scopeConfig() already returned the epoch-2 scope. A request only epoch 2
     * permits then goes out stamped epoch 1 -- an evidence line claiming
     * authorisation from an epoch that never granted it. Moving the writes
     * inside commitLock did not fix it (still 9/200); one reference does,
     * because there is only one write to observe.
     */
    public record Authorisation(long epoch, Map<String, List<String>> scope) { }
    private static final Authorisation DENIED = new Authorisation(0, Map.of());
    private volatile Authorisation committed = DENIED;

    private volatile String haltReason = null;
    private long epochCounter = 0;

    public BridgeClient(Path socketPath, String engagementId, String instanceId, Log log) {
        this.socketPath = socketPath;
        this.engagementId = engagementId;
        this.instanceId = instanceId;
        this.log = log;
    }

    public boolean isConfigured() { return configured.get(); }

    /**
     * @deprecated Two reads of {@link #committed}: a commit can land between
     * this call and a following {@link #scopeConfig()} (or vice versa), so
     * the pair straddles the commit and a decision can be made under one
     * epoch's scope while stamped with the other's epoch -- the natural read
     * order, {@code scopeConfig()} then {@code configEpoch()}, is the
     * dangerous one, since it yields the new epoch with the old, superseded
     * scope. Any decision that must send with an epoch and the scope that
     * epoch actually authorises has to read both in the one call
     * {@link #authorisation()} makes. Retained for callers that read only
     * this field.
     * @see BridgeClient#authorisation()
     */
    @Deprecated
    public long configEpoch() { return committed.epoch(); }

    /**
     * @deprecated See {@link #configEpoch()}: this is the other half of the
     * same straddle. Retained for callers that read only this field.
     * @see BridgeClient#authorisation()
     */
    @Deprecated
    public Map<String, List<String>> scopeConfig() { return committed.scope(); }

    /**
     * Epoch and scope in ONE read. Publishing them through a single reference
     * makes the STATE coherent, but configEpoch() then scopeConfig() is still
     * two reads of it and a commit can land between them: a busy poll measured
     * 11/400 there, against 32/400 for the two-field version this replaced.
     * Narrower is not closed. Anything that decides under a scope and then
     * stamps the epoch that granted it -- Plan 3's send path, and the evidence
     * line behind it -- must take the pair from here, once.
     */
    public Authorisation authorisation() { return committed; }

    /**
     * Is anything stopping issuance right now?
     *
     * THREE authorities, not one: this client's own two flags, plus the
     * {@link HaltSource} the send path enforces. It used to be the two flags
     * alone -- see HaltSource for the measurement -- and the flag it calls
     * `halted` is the `halt` FRAME and nothing else.
     *
     * WHAT A TRUE ANSWER DOES NOT MEAN. Every refusal that needs a request in
     * hand is still ahead: scope, method, dangerous path, unmanaged
     * credential, rate, budget, deadline. This answers "is the run stopped",
     * which is a necessary condition for issuing and not a sufficient one.
     * The only thing that decides a REQUEST is {@code Sender.issue}.
     *
     * Keeping the local `halted` flag as well as asking the source is not
     * redundancy for its own sake. The `halt` arm tells the switch FIRST and
     * sets this flag second, and `resume` clears this flag first and tells the
     * switch last; the AND is what leaves no window on either transition in
     * which this answers true while one of the two authorities is holding.
     */
    public boolean maySend() {
        return configured.get() && !halted.get() && heldReason() == null;
    }

    /**
     * The send path's halt authority, asked safely.
     *
     * FAIL CLOSED on an uninstalled source, and on one that throws. A client
     * that cannot find out whether the run is stopped has not found out that
     * it is running, and DENY-ALL is what this branch is. HxExtension installs
     * it before the dial, alongside the sink, so the null case is a wiring
     * failure rather than a state -- and a wiring failure that denies is one
     * somebody notices.
     */
    private String heldReason() {
        HaltSource s = haltSource;
        if (s == null) return "no halt source installed";
        try {
            return s.heldReason();
        } catch (Throwable t) {
            return "halt source threw: " + t;
        }
    }

    /** Drop to DENY-ALL. Returns whether the client had been configured.
     *  `configured` is cleared FIRST: maySend() reads only that and `halted`,
     *  so no observer sees permission outlive the scope behind it. */
    private boolean denyAll() {
        boolean was = configured.getAndSet(false);
        committed = DENIED;
        return was;
    }

    /** Throws unless {@link #maySend()} would answer true, and says which of
     *  the three authorities refused. Same caveat as maySend(): not throwing
     *  means the RUN is not stopped, not that a given request may go out. */
    public void checkMaySend() {
        if (!configured.get())
            throw new NotConfigured("not_configured: no configure frame acknowledged yet");
        if (halted.get())
            throw new NotConfigured("halted: " + (haltReason == null ? "no reason given" : haltReason));
        String held = heldReason();
        if (held != null)
            throw new NotConfigured("halted: " + held);
    }

    public void connect() throws IOException {
        if (closed) throw new IOException("this client is closed; make a new one");
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
        try {
            send(hello, new byte[0]);
        } catch (IOException | RuntimeException e) {
            closeChannel();          // F6: a dialled channel must not outlive a failed hello
            throw e;
        }
        // close() may have run while we were dialling: it had no channel to
        // shut and nothing configured to clear, so it left no trace here.
        if (closed) { closeChannel(); return; }

        readLoop();
    }

    private void readLoop() {
        // The Reader is created once, outside the loop, and owns its buffer
        // across iterations. Constructing one per iteration would lose every
        // frame that arrived in the same delivery as its predecessor.
        Frame.Reader reader = new Frame.Reader(in);
        try {
            while (true) {
                Frame.Decoded f = reader.read();
                if (!handle(f)) return;
            }
        } catch (Frame.PeerClosed | Frame.FrameError | IOException e) {
            // The expected ways a connection ends. Nothing to do here: the
            // finally block is what enforces the terminal state.
        } finally {
            // DENY-ALL on EVERY exit path, not just the ones named above. The
            // `return` out of the loop -- a protocol mismatch -- skips the
            // catch blocks entirely, and used to leave maySend() true with a
            // dead read loop and no control channel: the extension would keep
            // issuing requests that nothing could halt. This is the same shape
            // as the Python side's _reset() in _serve()'s finally, and for the
            // same reason.
            boolean wasConfigured = denyAll();
            closeChannel();
            if (wasConfigured) log.info("hx: control channel gone, deny-all");
        }
    }

    /** Test seam: is the dialled channel still open? Package-private and
     *  BridgeClient is final, so it cannot escape hx.bridge. F6 -- a channel
     *  outliving a failed hello -- has no other observable. */
    boolean channelIsOpen() {
        SocketChannel c = channel;
        return c != null && c.isOpen();
    }

    private void closeChannel() {
        try { if (channel != null) channel.close(); } catch (IOException ignored) { }
    }

    /** Package-private, not private: BridgeClientTest calls this directly to
     *  check that a closed client refuses a frame without needing to win a
     *  race first. BridgeClient is final, so nothing escapes hx.bridge.
     *
     *  Both this method's visibility and commitLock's are load-bearing for
     *  theCommitIsExclusiveWithClose(): that test holds commitLock on its own
     *  thread, calls handle() directly from a second thread so it parks on
     *  `synchronized (commitLock)` below, then calls close() -- which takes
     *  the same monitor -- reentrantly from the first thread. Make either
     *  member private again and that test cannot compile, let alone run; a
     *  later "tidy-up" that does so would silently delete the only
     *  deterministic coverage of the commit-lock guard, leaving only the
     *  scheduler-dependent race detector, which passes clean at 1-2 vCPU on
     *  broken code. */
    boolean handle(Frame.Decoded f) throws IOException {
        if (closed) return false;
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
                Map<String, List<String>> scope;
                try {
                    scope = ConfigBody.parse(f.body);
                } catch (Frame.FrameError e) {
                    // Unknown intent means DENY, not "carry on under the last
                    // intent". The likeliest trigger is an operator NARROWING
                    // scope with a key this jar predates: keeping the old,
                    // wider scope would then send exactly where they just said
                    // not to. Unlike engagement_mismatch and bad_frame above --
                    // neither of which is our peer trying to configure us --
                    // this one is, and it failed.
                    denyAll();
                    error(f, "bad_config", e.getMessage());
                    return true;
                }
                // BEFORE the commit, so a refused configure leaves no epoch
                // behind. An operator who was told `bad_config` must not find
                // a fresh config_epoch on the next result frame.
                String unusable = refuseConfigure(scope);
                if (unusable != null) {
                    denyAll();
                    error(f, "bad_config", unusable);
                    return true;
                }

                long epoch;
                synchronized (commitLock) {
                    // Either close() got here first -- and we must not undo it
                    // -- or it cannot arrive until this commit is complete and
                    // will then clear it. No ordering in between exists.
                    if (closed) return false;
                    epoch = ++epochCounter;
                    // One write publishes the epoch and the scope it
                    // authorises. Both are visible, or neither is.
                    committed = new Authorisation(epoch, scope);
                    configured.set(true);
                    // NOT halted.set(false). A configure re-authorises SCOPE,
                    // not ISSUANCE. An operator halts BECAUSE the scope went
                    // wrong and then pushes the corrected scope -- the most
                    // likely next action of all -- and clearing the halt here
                    // re-armed issuance with no `resume` on the wire, no log
                    // line, and both consoles reading "configured". Only a
                    // `resume` frame lifts a halt.
                }

                Map<String, Object> ack = new LinkedHashMap<>();
                ack.put("v", PROTOCOL_VERSION);
                ack.put("t", "configured");
                ack.put("id", f.header.get("id"));
                // The epoch WE committed, not whatever configEpoch() says now:
                // a close() between the commit and here zeroes it, and the ack
                // would then claim config_epoch 0 for a configure that was in
                // fact acknowledged under epoch N.
                ack.put("config_epoch", epoch);
                send(ack, new byte[0]);
            }
            case "send" -> {
                if (!engagementId.equals(f.header.get("engagement_id"))) {
                    // s6: every send carries it and the extension refuses a
                    // mismatch. Client A's bytes must never reach client B's
                    // report, and this is the cheapest place to say so.
                    error(f, "engagement_mismatch",
                          "send names engagement " + f.header.get("engagement_id")
                          + " but this extension serves " + engagementId);
                    return true;
                }
                SendHandler h = sendHandler;
                if (h == null) {
                    // "Nothing is wired up yet" is a state, not an exemption.
                    // EXTENSION_FAULT: this is not the operator failing to
                    // configure -- see the constant.
                    error(f, "not_configured",
                          EXTENSION_FAULT + "no send handler is installed");
                    return true;
                }
                Map<String, Object> reply;
                try {
                    // ONE read of the snapshot per decision, carried down as a
                    // parameter. The explicit receiver below is load-bearing:
                    // ChokepointTest counts the snapshot read across
                    // extension/src and expects exactly one, and it counts the
                    // dotted form -- a bare call here reads as zero. Write it
                    // with `this.` and leave it that way.
                    reply = h.handle(f.header, f.body, this.authorisation());
                } catch (Throwable ex) {
                    // An exception is never an implicit allow. Answer the
                    // caller so it gets an error class instead of a silent
                    // bridge_lost, then drop to DENY-ALL and close: a send path
                    // that threw is a send path we no longer understand, and
                    // the terminal state is the only honest place to be.
                    //
                    // `ex`, not `t`: handle() already has a String t, the
                    // frame type it switched on.
                    log.error("hx: send handler threw, deny-all: " + ex);
                    error(f, "not_configured",
                          EXTENSION_FAULT + "the send path threw: " + ex);
                    denyAll();
                    return false;
                }
                Object raw = reply.remove(BODY_KEY);
                send(reply, raw instanceof byte[] b ? b : new byte[0]);
            }
            case "identity" -> {
                if (!(f.header.get("deadline_us") instanceof Long)) {
                    // Required on every request frame, checked here for the
                    // reason the configure arm checks it: a sender that omits
                    // it is not speaking this protocol version properly.
                    error(f, "bad_frame", "request frame has no deadline_us");
                    return true;
                }
                if (!engagementId.equals(f.header.get("engagement_id"))) {
                    error(f, "engagement_mismatch",
                          "identity names engagement " + f.header.get("engagement_id")
                          + " but this extension serves " + engagementId);
                    return true;
                }
                // s5: "refused unless the extension is `configured` and not
                // halted, exactly as `send` is". BOTH checks, and in the send
                // path's order -- not_configured first, then the run-wide stop
                // -- because the two answers are opposite instructions and an
                // operator reading `halted` on an extension that was never
                // configured would go looking for a halt nobody raised.
                //
                // It is not merely symmetry. Registering a credential is the
                // one frame that puts a live secret into this JVM, and doing
                // it for a run that is stopped, or one whose scope was never
                // authorised, leaves it held for a send that may never be
                // authorised to use it.
                if (!configured.get()) {
                    error(f, "not_configured", "no configure frame acknowledged yet");
                    return true;
                }
                String stopped = halted.get()
                        ? "halt frame: " + (haltReason == null ? "no reason given" : haltReason)
                        : heldReason();
                if (stopped != null) {
                    error(f, "halted", stopped);
                    return true;
                }
                IdentitySink sink = identitySink;
                if (sink == null) {
                    // Wiring, not policy -- the same shape as a missing
                    // SendHandler, and EXTENSION_FAULT for the same reason:
                    // "the operator has not authorised this run" and "this jar
                    // is broken" are opposite instructions.
                    error(f, "not_configured",
                          EXTENSION_FAULT + "no identity sink is installed");
                    return true;
                }
                IdentityBody.Parsed body;
                try {
                    body = IdentityBody.parse(f.body);
                } catch (Frame.FrameError e) {
                    error(f, "bad_identity", e.getMessage());
                    return true;
                }
                try {
                    sink.register(body.identityId(), body.generation(), body.header(),
                                  body.value(), body.origins());
                } catch (StaleIdentity e) {
                    // A replayed or reordered frame, refused BY DESIGN. One
                    // frame is answered; the channel and the held identity
                    // both survive.
                    error(f, "stale_generation", e.getMessage());
                    return true;
                } catch (IllegalArgumentException e) {
                    error(f, "bad_identity", e.getMessage());
                    return true;
                }
                // THE BODY IS NEVER LOGGED. Spec s5: this is the only frame in
                // the protocol whose payload is a secret, and a debug line
                // added later is exactly how it would leak. The id and the
                // generation are not secrets and are what an operator needs to
                // see; `body.value()` and `body.header()`'s content reach no
                // log on either side, and `Parsed.toString()` is redacted so
                // that an exception message cannot become the leak either.
                log.info("hx: identity " + body.identityId()
                         + " registered at generation " + body.generation());
                Map<String, Object> ack = new LinkedHashMap<>();
                ack.put("v", PROTOCOL_VERSION);
                ack.put("t", "identity_registered");
                ack.put("id", f.header.get("id"));
                // Saying back WHICH identity is now at WHICH generation, so a
                // caller can check what it registered without asking for the
                // value. Not a secret and not derivable from `t` alone; the
                // registry holds this generation for this id by the time this
                // line runs, because an equal generation keeps the held entry
                // (which is at the same number) and a lower one threw above.
                ack.put("identity_id", body.identityId());
                ack.put("generation", (long) body.generation());
                send(ack, new byte[0]);
            }
            case "halt" -> {
                // NOT String.valueOf(): for an absent key that answers the
                // four-character string "null", which is neither null nor
                // blank, so HaltSwitch's "no reason given" fallback could
                // never fire for the only production caller and both
                // consoles showed the operator the word null.
                String why = f.header.get("reason") instanceof String r ? r : null;
                // The switch FIRST, this flag second. `halted` here governs
                // maySend()/checkMaySend(); the send path asks HaltSwitch, and
                // on the way DOWN the stricter authority is told first.
                if (!notifyHalt(true, why)) return false;
                halted.set(true);
                haltReason = why;
            }
            case "resume" -> {
                halted.set(false);
                // ...and on the way back UP it is told last, so no window
                // exists in which issuance is armed and the flag behind it is
                // not. Only a `resume` frame reaches here: a `configure` does
                // not lift a halt.
                if (!notifyHalt(false, null)) return false;
            }
            default -> {
                error(f, "unknown_frame", "unrecognised frame type " + t);
            }
        }
        return true;
    }

    /** Ask the {@link ConfigGuard}, safely. A guard that throws refuses: it
     *  is asked about an operator's intent, and an answer it could not
     *  produce is not permission. */
    private String refuseConfigure(Map<String, List<String>> scope) {
        ConfigGuard g = configGuard;
        if (g == null) return null;
        try {
            return g.refuse(scope);
        } catch (Throwable t) {
            return "the configure guard could not decide about this body: " + t;
        }
    }

    /**
     * Hand a halt or a resume to the switch. Returns false when the read loop
     * must drop to DENY-ALL and close.
     *
     * A sink that throws is the one case that cannot be shrugged off: the
     * frame that was supposed to stop issuance did not arrive anywhere, and an
     * exception is never an implicit allow. With no sink installed at all --
     * the state before HxExtension wires one up -- the local flag is the whole
     * answer, and nothing can be issued through a client that has no
     * SendHandler either.
     */
    private boolean notifyHalt(boolean halt, String reason) {
        HaltSink s = haltSink;
        if (s == null) return true;
        try {
            if (halt) s.halted(reason); else s.resumed();
            return true;
        } catch (Throwable t) {
            log.error("hx: halt sink threw, deny-all: " + t);
            denyAll();
            return false;
        }
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

    /** The two-body write, on the SAME monitor as the one-body one. Frames are
     *  built whole and written under one lock precisely so two threads cannot
     *  splice their bytes together -- and this one is written by the capture
     *  drain while the read loop may be answering a send. */
    private synchronized void send(Map<String, Object> header, byte[] first,
                                   byte[] second) throws IOException {
        out.write(Frame.encode(header, first, second));
        out.flush();
    }

    /**
     * Where the capture drain pushes what it has recorded.
     *
     * DECLARED HERE, like {@link HaltSink} and {@link SendHandler}, and for
     * the same reason: the package that CALLS the bridge depends on the
     * bridge, never the other way round. Returning a proxy-package type from
     * this class made the two packages import each other -- a cycle javac
     * does not mind and a reader does.
     *
     * SOURCE-AGNOSTIC, which is the half that actually breaks it. A
     * `dropped(long, Source)` still names the other package in its signature,
     * and an implementation of it still has to know how that enum is spelled.
     * So the caller does the spelling -- `Capture.sourceName`, where it
     * already lived -- and hands over a STRING, with `null` meaning "this
     * source has no spelling". The sink's whole job with a null is to omit
     * the key.
     *
     * FALSIFIABLE rather than asserted: ChokepointTest's
     * `theBridgeNamesNothingInTheProxyPackage` counts the needle in every
     * SHIPPED file of this package and requires zero, comments included.
     * WHAT IT DOES NOT COVER is this package's tests: `ChokepointTest.sources()`
     * walks `extension/src` only, and `extension/test` names the other package
     * freely -- BridgeClientTest does, at the point where it builds a record
     * to hand this sink. That is the right boundary rather than an oversight:
     * a test is not compiled into the jar, so it cannot reintroduce the cycle
     * the guard exists to keep out of it.
     *
     * EVERY METHOD ANSWERS WHETHER THE RECORD REACHED THE WIRE, and none
     * raises. Not raising is the same rule as "offering never blocks", one
     * layer down: an exception thrown back into the drain thread kills it,
     * and every record after it is lost silently. But "swallow and return"
     * alone was a second silence -- the drain read a normal return as
     * success and advanced its cumulative counter past drops that never left
     * the process. Measured shape: the queue saturates while the Python
     * harness restarts, 5,000 drops are counted, the write fails, one line
     * lands in Burp's log, the bridge reconnects, and `run.dropped_total`
     * reads 0. A BURP LOG LINE IS NOT THE COVERAGE FLOOR. False is.
     *
     * NOT A SEND, and not gated like one. `maySend()` answers "may this
     * extension ISSUE a request", and an exchange frame issues nothing: it
     * reports traffic that has ALREADY happened, through the proxy, under
     * S4's other enforcement point. Refusing to report it while halted would
     * mean an operator hitting stop also stopped the record of what had been
     * seen up to that moment -- the halt erasing its own evidence.
     */
    public interface ExchangeSink {
        /** True once the frame is on the wire. False means the record is
         *  lost and the caller is the only thing that can count it. */
        boolean exchange(Map<String, Object> header, byte[] request, byte[] response);

        /** `source` is the far side's spelling, or null for a source that has
         *  none. True once the report is on the wire; false leaves the whole
         *  outstanding total with the caller, to go out again. */
        boolean dropped(long n, String source);

        /** A request S4's second enforcement point refused. One body slot,
         *  empty: `server.py::_capture` hands `denial` and `dropped` to the
         *  sink as two empty halves. True once the frame is on the wire;
         *  false means the record is lost and the caller must count it. */
        boolean denial(Map<String, Object> header);
    }

    public ExchangeSink exchangeSink() {
        return new ExchangeSink() {
            public boolean exchange(Map<String, Object> header, byte[] request,
                                    byte[] response) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("v", PROTOCOL_VERSION);
                f.putAll(header);
                try {
                    send(f, request, response);
                    return true;
                } catch (Throwable e) {
                    log.error("hx: exchange frame undeliverable, record lost: " + e);
                    return false;
                }
            }

            public boolean dropped(long n, String source) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("v", PROTOCOL_VERSION);
                f.put("t", "dropped");
                f.put("n", n);
                // OMITTED, not defaulted, when the source has no spelling.
                // `hx.capture` documents what an absent `source` means and
                // answers the operator's run for it; writing "operator" here
                // would make this file a second, quieter place that decision
                // is taken, and the two would drift.
                if (source != null) f.put("source", source);
                try {
                    send(f, new byte[0]);
                    return true;
                } catch (Throwable e) {
                    log.error("hx: drop report undeliverable, coverage floor "
                              + "unrecorded: " + e);
                    return false;
                }
            }

            public boolean denial(Map<String, Object> header) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("v", PROTOCOL_VERSION);
                f.putAll(header);
                try {
                    // ONE body, and empty. A denial describes a request that
                    // produced no traffic: there are no bytes to carry, and
                    // `server.py::_capture` splits two bodies out of an
                    // `exchange` frame only.
                    send(f, new byte[0]);
                    return true;
                } catch (Throwable e) {
                    log.error("hx: denial frame undeliverable, record lost: " + e);
                    return false;
                }
            }
        };
    }

    public void close() {
        synchronized (commitLock) {
            closed = true;           // sticky: checked by connect() and handle()
            denyAll();
        }
        closeChannel();              // I/O outside the monitor
    }
}
```

- [ ] **Step 4: Write `HxExtension.java`**

The Burp entry point: read `-Dhx.socket`, `-Dhx.engagement` and
`-Dhx.instance` from system properties, build a `BridgeClient`, dial on a
daemon thread, and close it from an unloading handler.

The file itself is not reproduced here. Task 6 of
`2026-08-22-enforcement-send-path.md` rewrites it to construct the send path,
and that plan carries the full file; `tests/test_plan_matches_repo.py`
byte-compares every block against the file it names, so a second copy here
could only ever be a duplicate to keep in step or a lie about what the file
now contains.

- [ ] **Step 5: Run to verify it passes**

Run: `cd extension && ./test.sh`
Expected: both classes print `ALL PASS`, exit 0

- [ ] **Step 6: Commit**

```bash
git add extension
git commit -m "feat(bridge): java client dials in, stays deny-all until configured"
```

---

- [ ] **Step 6: fixes from the task review**

The code blocks in Steps 0-5 above have been corrected in place, so a fresh
implementer reading this plan top-to-bottom writes the right thing. If Steps
0-5 are already implemented, this step is the diff — five changes, the first
load-bearing.

**1. `readLoop()` leaked DENY-ALL through its one `return` path.** `handle()`
returns `false` on a protocol mismatch; the bare `return` skipped both catch
blocks, so `configured` stayed `true` and `configEpoch` kept its value with a
dead read loop and no control channel behind them. `maySend()` would answer
`true` forever, and the halt that is supposed to stop an assessment would have
nothing to arrive on. Replace the catch blocks with the caught set plus a
`finally`, and add `closeChannel()` — both shown in Step 3's corrected block.

The invariant, stated once: **leaving `readLoop()` by any path means DENY-ALL.**
Not "by the paths we thought of".

**2. `close()` zeroed `configured` but not `configEpoch` or `scopeConfig`,**
leaving a closed client reporting a live epoch and a stale scope. Corrected in
Step 3's block.

**3. The fake's `configure` frame omitted `deadline_us`,** which the client
correctly rejects as `bad_frame` — the real peer stamps `id` and `deadline_us`
on every frame `_request()` sends, and `configure()` is its only caller. The
fake was wrong, not the client. Corrected in Step 1's block. Do not "fix" this
by relaxing the client's validation.

**4. `private final Object log` was stored and never used,** typed `Object`
only to dodge a compile-time Montoya dependency in tests. Replaced by the
`BridgeClient.Log` interface, an adapter in `HxExtension`, and
`FakeMontoya.Logger implements BridgeClient.Log` — all shown above. The
`finally` block now logs the transition into DENY-ALL, which is the one event
Task 5 will most want in Burp's output when a handshake misbehaves.

**5. On the Python side, an `error` reply to `configure` was reported as
"peer acknowledged configure without a config_epoch"** — technically true and
actively misleading, since the peer said exactly what was wrong and the message
threw it away. `configure()` now surfaces the reply's `class` and `detail`;
corrected in Task 3's `configure()` above. Add this test to
`tests/test_bridge_server.py`:

```python
def test_an_error_reply_to_configure_reports_what_the_peer_said(srv):
    c = _connected(srv)
    try:
        out = {}

        def go():
            try:
                srv.configure({"scope.include": ["https://a/*"]},
                              scope_sha256="x", profile="production")
            except server.BridgeError as exc:
                out["err"] = str(exc)

        t = threading.Thread(target=go)
        t.start()
        header, _ = codec.FrameReader(c).read()
        c.sendall(codec.encode({"v": 1, "t": "error", "id": header["id"],
                                "class": "engagement_mismatch",
                                "detail": "e-1 != SOMEONE-ELSE"}))
        t.join(timeout=5)
        assert not t.is_alive()

        assert "engagement_mismatch" in out["err"], out
        assert "SOMEONE-ELSE" in out["err"], out
        assert "without a config_epoch" not in out["err"], out
    finally:
        c.close()
```

Verified against the real server before it was written here: passes, and the
Python suite stays green at 160.

- [ ] **Step 7: Run everything and commit**

```bash
extension/test.sh && extension/build.sh
.venv/bin/python -m pytest tests/ -q      # 161 passed
git add extension src/hx/bridge/server.py tests/test_bridge_server.py
git commit -m "fix(bridge): deny-all on every exit from the read loop"
```

---

- [ ] **Step 8: what two more review rounds changed, and what is NOT covered**

The code blocks above are the **final** files, synced from the repository — not
the first draft plus a list of patches. Transcribe them as they stand. This
note exists so the shape of that code is legible, and so nobody re-derives a
defect that was already paid for.

**`close()` is sticky and exclusive.** Three demonstrated ways an extension
could send after being closed: Burp's unloading handler firing before the dial
completed (an *unloaded* extension holding a live control channel), `close()`
followed by `connect()` on the same object, and a `configure` already sitting
in the `Reader`'s buffer — which needs no syscall, so shutting the socket does
not stop it being processed. Hence `volatile boolean closed`, checked in
`connect()` and in `handle()`, and a `commitLock` making the commit and
`close()` mutually exclusive. A commit-then-recheck was tried first and
rejected: it makes the window nanoseconds instead of ~9 us, but narrowness is
an incidental property of how long `send(ack)` takes.

**Epoch and scope are one value.** `configEpoch()` and `scopeConfig()` as two
volatile fields were measured returning an incoherent pair 5-9 times in 200: a
live client reporting epoch 1 while already serving the epoch 2 scope. A
request that only the new scope permits then gets stamped with the old epoch in
evidence — an audit line claiming authorisation from an epoch that did not
grant it. Publishing through one `Authorisation` reference was still not enough:
two reads of that reference straddle a commit 11 times in 400. Only
`authorisation()`, returning the pair in a single read, measured 0/400.

> **Plan 3 must read `authorisation()` once per decision.** Calling
> `configEpoch()` and `scopeConfig()` separately on the send path reintroduces
> the straddle. Nothing in the type system enforces this yet.

**An unparseable configure denies.** It does not keep the previous scope. The
trigger is version skew — an operator NARROWING scope with a key this jar
predates — where retaining the old wider scope sends exactly where they just
said not to. `engagement_mismatch` and `bad_frame` are unchanged: neither is
our peer trying to configure us.

**Coverage, stated honestly.** These fixes have **no test behind them** and a
reviewer confirmed reverting each one fails nothing:

| Unguarded | Why |
|---|---|
| `volatile` on `channel`/`in`/`out` and on `HxExtension.client` | a visibility bug needs a weakly-ordered CPU to observe; x86 hides it |
| the `Reader` single-thread comment | a comment |
| `StringBuffer` in `FakeMontoya` | races only under a schedule the suite does not force |
| the `@Deprecated` annotations on `configEpoch()`/`scopeConfig()` | an annotation; verified by inspection only |
| the **top-of-`handle()`** `closed` guard | deleting it alone fails nothing — the commit-lock guard catches every exit reachable today. A coverage hole, not a live defect |
| `Frame.Reader`'s shrink branch | never taken: the largest frame in the suite is 100 000 bytes, the trigger is 4 MB |
| `HxExtension`'s unloading handler and its missing-`-Dhx.socket` branch | `initialize()`'s happy path is exercised end to end by Task 5's integration test — a real Burp loads this class and dials in — but neither of these two branches is, and no unit test exists; that still needs a MontoyaApi fake |
| `make_home()` (Task 5) | nothing asserts what it builds: the `burpbrowser` symlink, the deleted `.userPrefs` lock, the copied `.BurpSuite` tree. A mistake there surfaces as a Burp that will not start, blamed on Burp |
| the rest of `missing()` (Task 5) | `tests/test_burp_fixture.py` covers the EULA, stale-jar and `.BurpSuite` guards in both directions, but not the burp-jar row, and nothing checks that the `skipif` wiring actually consumes what `missing()` returns |
| the `finally` reaper in both integration tests (Task 5) | proving it would need a test that fails mid-test and then reads the process table. A leak is a 900 MB JVM outliving the run, never a red test |
| "the fast suite never launches Burp" (Task 5) | deleting `addopts` from `pyproject.toml` fails nothing. It just makes `pytest` 13 seconds slower and starts two JVMs — which is what the property is for |

That list is longer than the three rows this table shipped with, and it is
still not everything: a reviewer sabotage-verified **fourteen** more behaviours
with no failing check, including the single-read `authorisation()`, the
one-write publication, the ack epoch hoist, and the `gen`/`_conn` guard on the
Python reset. Treat this table as "the ones worth naming", never as "everything
else is covered".

Do not add a test that "covers" these by asserting something adjacent. An
earlier commit in this task claimed every fix was sabotage-verified when three
were not; the honest record is this table.

**The guard is `theCommitIsExclusiveWithClose`.** Not the detector beside it,
and not the check that calls `handle()` directly on a closed client — that one
feeds a `configure` frame, so the commit-lock guard satisfies it whether or not
the top-of-`handle()` guard exists, and it cannot discriminate between them.

`closeIsTerminalAgainstTheReadLoop` is a **detector**, and a scheduler-dependent
one. Against a defective client it measured 19-20/20 on 24 cores but **0/20 on
one core, and 0/20 in two runs of three on two cores** — a clean, silent pass on
broken code, on the machine shape CI most often has.

`theCommitIsExclusiveWithClose` does not depend on scheduling at all: the test
thread holds `commitLock`, so the helper parks inside `handle()` by
construction, and monitor reentrancy lets `close()` through. It fails 100% of
runs at 1, 2 and 24 cores when the guard is removed.

> If you change either `closed` guard in `handle()`, check it against
> `theCommitIsExclusiveWithClose`. Do **not** judge by the detector's
> resurrection count: it reads 0/20 on correct and broken code alike at low
> core counts. Both `commitLock`'s package-private visibility and `handle()`'s
> exist to make that test possible — neither is an oversight to tidy up.

---

### Task 5: End-to-end against real headless Burp

**Files:**
- Create: `tests/__init__.py` — **required**: without it `from tests.integration import ...` fails with `ModuleNotFoundError: No module named 'tests'`, verified
- Create: `tests/integration/__init__.py`
- Create: `tests/integration/test_real_burp.py`
- Create: `tests/integration/burp_fixture.py`
- Create: `tests/test_burp_fixture.py` — the fixture's own prerequisite checks, in the **fast** suite
- Modify: `pyproject.toml` — register the `integration` marker

**Interfaces:**
- Consumes: `hx.bridge.server.BridgeServer`, `extension/build/hx-bridge.jar`, and the mtimes of `extension/src/**/*.java` (the stale-jar check)
- Produces, all in `tests.integration.burp_fixture`:
  - `missing() -> list[str]` — the unsatisfied prerequisites, each named
  - `burp_available() -> bool` — `not missing()`
  - `make_home(workdir: Path) -> Path` — a private `$HOME` per run
  - `launch_burp(socket_path: Path, engagement_id: str, workdir: Path) -> subprocess.Popen`
  - `wait_for(predicate, timeout: float = 90.0, interval: float = 0.5) -> bool`

All five are public names in the module and this block used to list two of
them. Under-declaring is the same defect a reviewer caught in Task 4's header,
and it costs the same way: the next task reads the block, believes it, and
writes a call with the wrong arity — `launch_burp` takes a `workdir`, and
always has.

- [ ] **Step 1: Register the marker so the slow test is opt-in**

```toml
# add to pyproject.toml
[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
markers = [
    "integration: loads a real headless Burp Suite; needs the jar (~5s to hello, ~20s per test)",
]
addopts = "-m 'not integration'"
```

`addopts` keeps the fast suite fast by default. The integration test runs with `pytest -m integration`.

- [ ] **Step 2: Write the fixture**

```python
# tests/integration/burp_fixture.py
"""What the RIG adds to `hx.session`, and nothing that `hx.session` already is.

The launcher, the private home, the listener config, the port readback and the
loopback check all USED to live here, and the demo script imported them from
the test tree. They are `hx.session`'s now, and this module re-exports them so
that the code a consultant runs and the code these thirty tests certify are one
body of code rather than two that agree today.

What is left is genuinely test-only: the prerequisite checks that decide
whether this MACHINE can run a real Burp at all (a skip) as against whether
somebody forgot to run `extension/build.sh` (a failure), and the second
BurpExtension the proxy measurements need.

Everything below was established empirically, most of it the hard way:
  - Burp asks for a licence key on stdin; a bare newline selects Community.
  - The EULA gate is a single Java Preferences key, burp.eula.
  - Launching with -cp instead of -jar means the jar manifest's Add-Opens is
    ignored, so every --add-opens must be repeated on the command line.
  - Burp throws `java.lang.Error: no ComponentUI class` twice while building a
    Swing UI it cannot have under -Djava.awt.headless=true. This is NOISE. A
    known-good instance logs it identically and runs for hours. Do not chase it.
  - api.logging().logToOutput() does NOT reach the process stdout. You cannot
    detect that the extension loaded by reading the log -- observe the bridge
    instead. `hello` arriving IS the readiness signal.
  - Startup to hello measured at ~5s, not the ~40s originally assumed.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

from hx import session
from hx.session import (          # noqa: F401  -- re-exported for the rig
    ADD_OPENS,
    EXT_JAR,
    EXT_SRC,
    PROXY_CONFIG,
    SessionError,
    _free_port,
    _is_loopback,
    _jar_mtime,
    _listening_sockets,
    _newest_source_mtime,
    extension_problem,
    find_burp_jar,
    listener_ports,
    make_home,
    not_loopback_only,
    proxy_port,
    second_proxy_port,
    seed_home,
    wait_for,
    write_listener_config,
)

LAB = Path(os.environ.get("HX_BURP_LAB", session.DEFAULT_LAB))
SEED_HOME = LAB / "burphome"          # copied from, never run against

# The rig's seed is the lab's curated home rather than the operator's own,
# which is what `hx.session.seed_home()` returns by default. Both launchers
# below say so with `seed=SEED_HOME`, in code, on every call -- NOT through
# `$HX_BURP_SEED_HOME`, which only an autouse pytest fixture could set and
# which therefore left this module's two non-pytest callers, the demo scripts,
# checking this home and copying the operator's.

try:
    BURP_JAR: Path | None = find_burp_jar()
    _NO_BURP_JAR: str | None = None
except (SessionError, OSError) as exc:
    # NOTHING MAY RAISE AT IMPORT. `find_burp_jar()` raises when the lab holds
    # no jar -- or two, which is an error rather than a guess -- and this
    # module is imported during COLLECTION for the whole repository. An escape
    # here is not a skipped suite, it is `Interrupted: 1 error during
    # collection` with zero tests run, fast suite included. That exact shape
    # has bitten twice already, once from `_eula_accepted` raising
    # UnicodeDecodeError on a torn prefs.xml. So the reason is HELD and
    # reported by missing(), which is the function whose whole contract is
    # that it names what is absent instead of raising.
    BURP_JAR = None
    _NO_BURP_JAR = str(exc)


def missing() -> list[str]:
    """Which prerequisites are absent, for a skip reason that names them.

    A bare False here once sent a debugger into a Burp stack trace when the
    real problem was an unbuilt extension jar: Burp starts happily with a
    classpath entry that does not exist, loads no extension, and never dials
    in. Say which path is missing.

    NOTHING may raise out of this function. It runs at import time, so an
    exception here is not a skipped test -- it is `Interrupted: 1 error during
    collection` for the entire repository, fast suite included. That has now
    happened twice, both times from code added to make this function safer:
    once from a UnicodeDecodeError reading a torn prefs.xml, once from a
    dangling symlink under the source tree.

    The individual checks are not enough on their own. Path.exists() and
    Path.is_dir() swallow only a narrow errno whitelist -- ENOENT, ENOTDIR,
    EBADF, ELOOP -- so EACCES, ESTALE and ENOTCONN still propagate. A
    permission-tightened lab directory, a CI runner under another uid, or a
    stale NFS mount is enough. Reproduced directly:

        PermissionError [Errno 13] ... burpsuite_desktop_v2026.7.3.jar

    So the whole body is wrapped, and an unreadable prerequisite is reported
    as a missing one.
    """
    try:
        return _missing()
    except OSError as exc:
        return [f"prerequisites under {LAB} could not be checked: {exc}"]


def _burp_jar_row() -> str | None:
    """The Burp jar's absence, however it was discovered -- or None.

    Two ways to have no jar and one row for both: `find_burp_jar()` failed at
    import (no jar in the lab, or two, or an unreadable one) and left its own
    message, or it named a path that has since gone. The first message is the
    product's own and names all three places it looked; the second names the
    path, which is what the rows below do.
    """
    if BURP_JAR is None:
        return _NO_BURP_JAR
    if not BURP_JAR.exists():
        return f"burp jar: {BURP_JAR}"
    return None


def _jar_problem() -> str | None:
    """The ONE place the jar's state is judged: "missing", "stale", "future", None.

    One function because the first version of this split had two, and they had
    already diverged in the commit that created them: `_missing()` special-
    cased a future-dated source and `unbuilt()` did not. That is not a
    cosmetic drift. A future mtime cannot be cleared by rebuilding -- no jar
    can be stamped later than a source dated years ahead -- and `_missing()`'s
    own comment records it being reproduced ("two honest rebuilds, still
    reported stale both times"). Routing it to a hard FAIL told the operator
    to run a script that provably cannot help, permanently.

    So the three outcomes are distinguished HERE, once, and routed by who can
    fix them: "missing" and "stale" are build.sh's, "future" is the clock's.

    `hx.session.extension_problem()` makes the same three-way judgement for
    the product and phrases it as a sentence for an operator. This one stays
    because the rig routes the three outcomes to three DIFFERENT verdicts --
    fail, skip, silence -- where the product has only one, and a caller cannot
    recover the distinction from prose.
    """
    if not EXT_JAR.exists():
        return "missing"
    newest = _newest_source_mtime()
    if newest > time.time() + 60:
        return "future"
    if newest > _jar_mtime():
        return "stale"
    return None


def unbuilt() -> list[str]:
    """Build products of THIS repo that are absent or stale. These must FAIL.

    `missing()` answers "can this machine run Burp at all" -- a question whose
    honest answer on someone else's laptop is no, and a skip. This one answers
    "did you run build.sh", whose answer is always yes-or-you-forgot, and a
    skip there is the failure mode this project keeps finding: a missing
    artefact turns into a silent green.

    It is not hypothetical. Task 1's fix round inherited a tree whose jar was
    stale, `-m integration` reported all 17 tests SKIPPED, and the baseline
    recorded one commit earlier as "integration 17 passed" was not
    reproducible as committed. The same shape had just been fixed one level
    down for the probe source; it was still open here.

    Kept separate from `missing()` rather than merged into it because the two
    have opposite correct behaviours, and a single list forces one of them to
    be wrong.

    Returns EMPTY when the machine cannot build at all. `build.sh` needs the
    montoya jar from the same lab `_environment_missing()` reports and exits 1
    without it, so telling a contributor with no lab to "run extension/build.sh"
    sends them to a script that cannot succeed. A build product is only
    independent of the machine when the machine can build it.

    Wrapped for the same reason `missing()` is: this runs at IMPORT TIME
    through test_real_burp's skipif, and an exception here is not a skipped
    test, it is `Interrupted: 1 error during collection` for the entire
    repository -- 396 fast tests reporting nothing. That was measured against
    a lab directory at mode 000, and `missing()`'s docstring already records
    the same hazard biting twice before.
    """
    try:
        if _environment_missing():
            return []
        problem = _jar_problem()
        if problem == "missing":
            return [f"extension jar is missing (run extension/build.sh): {EXT_JAR}"]
        if problem == "stale":
            return ["extension jar is older than its sources (run extension/build.sh)"]
        return []
    except OSError as exc:
        return []


def _environment_missing() -> list[str]:
    """Prerequisites this MACHINE may legitimately not have. Never the jar.

    Split out so a caller can take the subset it actually depends on.
    `probe_missing()` is the reason: the probe compiles its own class and
    launches with `--developer-extension-class-name=hx.proxy.Probe`, so it
    never loads the extension jar -- yet it inherited the jar's rows through
    missing() and a STALE JAR silenced all three of Task 1's measurements.
    A prerequisite that is not one is still a skip, and a skip still reports
    green.
    """
    try:
        return _environment_missing_unguarded()
    except OSError as exc:
        return [f"prerequisites under {LAB} could not be checked: {exc}"]


def _environment_missing_unguarded() -> list[str]:
    absent = []
    if (row := _burp_jar_row()) is not None:
        absent.append(row)
    if not (SEED_HOME / ".java").is_dir():
        absent.append(f"seed burp home: {SEED_HOME / '.java'}")
    elif not _eula_accepted():
        absent.append(f"burp.eula not accepted in {SEED_HOME / '.java'}")
    if not (SEED_HOME / ".BurpSuite").is_dir():
        absent.append(f"seed burp home: {SEED_HOME / '.BurpSuite'}")
    return absent


def _missing() -> list[str]:
    absent = []
    if (row := _burp_jar_row()) is not None:
        absent.append(row)
    if not EXT_JAR.exists():
        absent.append(f"extension jar (run extension/build.sh): {EXT_JAR}")
    elif (newest := _newest_source_mtime()) > time.time() + 60:
        # A future timestamp is a broken clock, not a stale jar, and treating
        # it as staleness disables the integration suite PERMANENTLY: no
        # rebuild can stamp the jar later than a source dated years ahead.
        # Reproduced -- two honest rebuilds, still reported stale both times.
        absent.append(
            f"a source under {EXT_SRC} is dated in the future "
            f"({newest - time.time():.0f}s ahead); fix the clock or re-touch it"
        )
    elif newest > _jar_mtime():
        absent.append("extension jar is older than its sources (run extension/build.sh)")
    if not (SEED_HOME / ".java").is_dir():
        absent.append(f"seed burp home: {SEED_HOME / '.java'}")
    elif not _eula_accepted():
        # Checked because the failure mode is silence: Burp waits at the EULA
        # gate forever and the test times out with nothing in the log to say
        # why. The pref lives in the seed home, so a cleared or regenerated
        # home takes it with it.
        absent.append(f"burp.eula not accepted in {SEED_HOME / '.java'}")
    if not (SEED_HOME / ".BurpSuite").is_dir():
        # make_home() copies this tree as well as .java. Checking only .java
        # let burp_available() return True and the launch then die on a
        # FileNotFoundError halfway through the copy -- reproduced -- which is
        # precisely the unnamed failure this function exists to prevent.
        absent.append(f"seed burp home: {SEED_HOME / '.BurpSuite'}")
    return absent


def _eula_accepted() -> bool:
    """The rig's seed home, judged by the product's reader.

    The byte search and the lesson behind it (a torn 1.75 MB prefs.xml makes
    read_text() raise UnicodeDecodeError, which is not an OSError, so it
    escaped this function, escaped missing(), and turned every pytest run in
    the repo into a collection error) live in `hx.session._eula_accepted`.
    Only WHICH home is the rig's business.
    """
    return session._eula_accepted(SEED_HOME)


def burp_available() -> bool:
    return not missing()


def launch_burp(socket_path: Path, engagement_id: str, workdir: Path,
                sentinel: Path, crawler_port: int = 0) -> subprocess.Popen:
    """`hx.session.launch_burp`, with the two facts that are the RIG's to say.

    The launcher itself is the product's, which is the whole point: the
    `--add-opens` list, the `-Dhx.*` properties, the two loopback-only
    listeners and the log-to-a-file-never-a-pipe rule are now certified by
    these thirty tests as the code a consultant's `hx capture start` runs,
    rather than as a copy of it that agreed on the day it was written.

    Three arguments are still this side's. `jar` is the one this lab holds --
    resolved once at import, so a test's failure names the same jar
    `missing()` does. `instance` is "integration" because the rig identifies
    itself as the rig: `test_real_burp` asserts on `hello["instance_id"]`, and
    an operator reading a bridge log should be able to tell a test run from a
    session they started.

    `seed=SEED_HOME` IS THE ONE `missing()` CHECKED, and passing it is not
    tidiness. `session.make_home` copies `seed_home()` by default -- the
    operator's own `$HOME` -- which is right for a consultant and wrong for
    every caller here, and for one round of this task it was steered by an
    autouse fixture setting `$HX_BURP_SEED_HOME`. A fixture only runs under
    pytest. `scripts/demo_capture.py` and `scripts/demo_gate.py` call this
    function too: they guarded on `missing()`, which reports on `SEED_HOME`,
    and then copied the operator's live `~/.BurpSuite/sessions` -- real client
    project state on a consultant's machine -- into a temporary directory.
    Checking one home and copying another is the exact disagreement this
    argument removes, for every caller rather than for the ones pytest owns.
    """
    return session.launch_burp(
        socket_path, engagement_id, workdir,
        sentinel=sentinel,
        # Not `BURP_JAR` outright: when the import-time search failed this is
        # None, and calling through raises find_burp_jar's own message, which
        # names all three places it looked.
        jar=BURP_JAR if BURP_JAR is not None else find_burp_jar(),
        instance="integration",
        crawler_port=crawler_port,
        seed=SEED_HOME)


# ---------------------------------------------------------------------------
# The probe launcher, for docs/burp-proxy-measurements.md and the tests that
# keep it true. Everything below is about one question: which proxy listener
# did this request arrive on?
#
# WHY THE PROBE'S SOURCE IS UNDER tests/ AND NOT UNDER extension/src.
# It is a second BurpExtension, and it registers a second proxy request
# handler. Two structural checks forbid that in the shipped tree, both
# rightly: ChokepointTest asserts burp.* is imported by HxExtension.java and
# nothing else, and Plan 4's Task 7 asserts there is exactly one
# registerRequestHandler. It was written under extension/src to take the
# measurements and deleted from there in the same task.
#
# Deleting it outright would have left test_proxy_facts.py skipping forever,
# and a test that can only skip is not the "goes red when Burp changes" half
# of that deliverable -- it is the silence this repository keeps removing. So
# the source lives beside the test that needs it and is compiled into a
# throwaway directory per run, against the Burp jar itself: Burp ships the
# whole Montoya API inside burpsuite_desktop_v2026.7.3.jar (997 entries under
# burp/api/montoya/), so this adds no prerequisite that -m integration did not
# already have.
# ---------------------------------------------------------------------------

# PROXY_CONFIG, _free_port and write_listener_config used to live here, then
# moved above launch_burp so the two launchers shared ONE spelling of
# `listen_mode: loopback_only`. They are `hx.session`'s now and imported at
# the top of this file, which makes that one spelling the product's. The
# explanation of WHY a listener has to come from a config file at all stays in
# launch_probe's docstring below, where it was measured.
PROBE_SRC = Path(__file__).resolve().parent / "probe" / "hx" / "proxy" / "Probe.java"
PROBE_CLASS = "hx.proxy.Probe"


def probe_missing() -> list[str]:
    """What the probe needs FROM THIS MACHINE beyond what missing() covers.

    Environment facts only, and the split is not tidiness. PROBE_SRC used to
    be in this list, which made an absent probe a SKIP: renaming
    tests/integration/probe/ produced `3 skipped in 0.03s` -- no error, no
    diagnostic -- and the default run's summary line announces DESELECTED
    integration tests, not skipped ones. So the three facts eight tasks rest
    on stopped being checked with nothing red anywhere.

    A Burp jar and a JDK are things a machine may legitimately not have. A
    file this repository ships is not one of those. See probe_source_missing().

    Kept out of missing() deliberately. That function runs at import time for
    the whole repository and its contract is that nothing escapes it; this one
    is called by a single fixture and may be as ordinary as it likes.
    """
    absent = _environment_missing()
    if shutil.which("javac") is None:
        absent.append("javac (a JDK, not just a JRE) to compile the probe")
    return absent


def probe_source_missing() -> str | None:
    """Why the probe cannot be compiled at all -- or None when its source is here.

    Separate from probe_missing() so the caller can treat it differently, and
    the caller must: this is a FAILURE, not a skip. The scenario is specific
    enough to answer in the message -- somebody reads Task 1's brief, sees
    "Step 8: Delete the probe", and deletes the wrong copy.
    """
    if PROBE_SRC.exists():
        return None
    return (
        f"the probe's source is gone: {PROBE_SRC}. This is not a missing "
        "environment prerequisite, it is a file this repository ships, and "
        "without it the three measurements in test_proxy_facts.py -- the only "
        "check that Burp's proxy still behaves the way Plan 4 was designed "
        "around -- cannot run at all. If it was deleted because Task 1's brief "
        "says Step 8 deletes the probe: that step removed it from "
        "extension/src, where a second registerRequestHandler breaks "
        "ChokepointTest and Task 7. It belongs here. Restore it with "
        "`git checkout tests/integration/probe/`."
    )


def _compile_probe(workdir: Path) -> Path:
    """The probe's classes, built fresh per run into a directory nothing keeps.

    Compiled against BURP_JAR rather than montoya-api.jar so that the only
    prerequisite is the one the integration suite already has. --release 21
    matches extension/build.sh: Burp loads this class into the same JVM.
    """
    classes = workdir / "probe-classes"
    classes.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["javac", "--release", "21", "-nowarn", "-Xlint:-options",
         "-cp", str(BURP_JAR), "-d", str(classes), str(PROBE_SRC)],
        check=True, capture_output=True, text=True)
    return classes


def launch_probe(workdir: Path, out: Path,
                 extra_listener_port: int = 0) -> subprocess.Popen:
    """Burp running hx.proxy.Probe, with a SECOND proxy listener.

    The second listener is the whole point of Q1: one Burp, two ports, and the
    question is whether the extension can tell which one a request came in on.
    `extra_listener_port=0` means the caller does not care which port it gets;
    read the real ones back with proxy_port() and second_proxy_port().

    Burp Community has no API for creating a listener -- `burp.api.montoya.
    proxy.Proxy` offers registerRequestHandler, registerResponseHandler,
    registerWebSocketCreationHandler, history and intercept, and nothing that
    opens a port. So the second listener comes from a PROJECT CONFIG FILE via
    `--config-file`, which Community does accept. Both listeners are written
    explicitly, including the first: a config that named only the second would
    leave the first wherever Burp's defaults put it, which is the 8080 that
    _free_port() exists to avoid.

    `loopback_only` is not decoration. Nothing in this project has ever sent a
    request off this machine, and a proxy listener on 0.0.0.0 is an open relay
    on whatever network the laptop is attached to. It is also not self-
    enforcing: this string was the whole of the protection until
    not_loopback_only() was written, and changing it to `all_interfaces` left
    the suite green with the proxy bound to `*`. Callers must run that check
    once the listeners are up -- test_proxy_facts.py's fixture does.
    """
    # seed=SEED_HOME for the same reason bf.launch_burp passes it: make_home's
    # default is the operator's own home, and this is the one missing() checked.
    home = make_home(workdir, seed=SEED_HOME)
    classes = _compile_probe(workdir)
    write_listener_config(workdir, extra_listener_port)
    log = (workdir / "burp.log").open("wb")
    cmd = [
        "java", "-Djava.awt.headless=true", f"-Duser.home={home}",
        f"-Dhx.probe.out={out}",
        # The probe's classes in place of the shipped extension jar. Burp
        # loads exactly the one class named below, so EXT_JAR on the classpath
        # would not load HxExtension -- it is left off because the probe does
        # not need it, and because a jar on the path of a measurement run is a
        # thing a later reader has to rule out.
        *ADD_OPENS, "-cp", f"{BURP_JAR}:{classes}",
        "burp.StartBurp",
        f"--developer-extension-class-name={PROBE_CLASS}",
        f"--config-file={workdir / PROXY_CONFIG}",
        "--disable-auto-update",
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=log,
                            stderr=subprocess.STDOUT, cwd=LAB)
    proc.stdin.write(b"\n\n")
    proc.stdin.flush()
    return proc
```

- [ ] **Step 3: Write the failing test**

```python
# tests/integration/test_real_burp.py
import hashlib

import pytest

from hx import halt as halt_mod
from hx.bridge import server
from hx.store import db as db_mod
from hx.store.paths import secure_mkdir
from tests.integration import burp_fixture as bf


@pytest.fixture(autouse=True)
def _built():
    """An unbuilt or stale extension jar is a FAILURE here, not a skip.

    These two tests exist to certify the bridge against a real JVM. Run
    against a jar older than its sources they certify an artefact that no
    longer matches the code -- and the skip that used to hide that reported
    green. Measured: a stale jar skipped all 17 integration tests while the
    commit that caused it recorded them as passing.
    """
    problems = bf.unbuilt()
    if problems:
        pytest.fail("unbuilt: " + ", ".join(problems))

pytestmark = pytest.mark.integration


def _operator_halt(workdir, engagement_id):
    """`BridgeServer` requires one -- the same call HxExtension makes about
    `-Dhx.halt_sentinel`, for the same field. A harness with no engagement of
    its own supplies a sentinel in a directory of its own, which is what this
    builds.

    These two tests failed for one day, and the reason is worth keeping.

    Task 6 made `-Dhx.halt_sentinel` mandatory -- HxExtension.initialize()
    returns early with "extension idle" without it -- and did not update
    `bf.launch_burp`. The integration tests are deselected from the default
    run, so nothing said so. The extension never dialled, `srv.state` never
    reached "connected", and both tests timed out after 90s.

    The first diagnosis was that Burp 2026.7.3 dies at startup under this
    machine's JRE 26, because burp.log ends in `java.lang.Error: no ComponentUI
    class for: burp.Zc7w` on the EventDispatchThread. THAT DIAGNOSIS WAS WRONG,
    and the thing that disproved it is worth copying: burp-lab's
    `harness-burp.log`, written by a run that demonstrably worked, is BYTE-FOR-
    BYTE the same 6423 bytes with the same two ComponentUI errors and the same
    tail. That log is what healthy headless Burp looks like -- Burp catches the
    Swing failure and carries on, and nothing else writes to stdout afterwards.

    Two lessons, both general. A log that ENDS at an error has not necessarily
    FAILED at that error. And `api.logging().logToError` goes to Burp's own
    extension log, not to stdout, so "no hx lines in burp.log" is not evidence
    the extension did not run.

    With the sentinel passed, both tests pass in ~14s.
    """
    root = workdir / "engagement"
    secure_mkdir(root)
    conn = db_mod.connect(root / "hx.db")
    db_mod.init_schema(conn)
    conn.execute("INSERT INTO engagement(id, name, client, created_us, status)"
                 " VALUES(?,'Integration','Integration',1,'active')",
                 (engagement_id,))
    return halt_mod.OperatorHalt(root, conn)


@pytest.mark.skipif(bool(bf._environment_missing()) and not bf.unbuilt(),
                    reason=f"missing: {', '.join(bf._environment_missing())}")
def test_real_burp_dials_in_and_handshakes(tmp_path):
    """The whole point of this plan, proved against the real container.

    Fakes prove the logic; only this proves Burp actually loads the extension
    and that the socket handshake works end to end.
    """
    srv = server.BridgeServer(
        tmp_path / "hx.sock", engagement_id="e-integration",
        operator_halt=(oh := _operator_halt(tmp_path, "e-integration")))
    srv.start()
    proc = None
    try:
        proc = bf.launch_burp(srv.socket_path, "e-integration", tmp_path,
                              oh.sentinel_path)

        assert bf.wait_for(lambda: srv.state == "connected"), \
            "Burp never completed the hello handshake"

        assert srv.hello["engagement_id"] == "e-integration"
        assert srv.hello["instance_id"] == "integration"
        assert "2026" in srv.hello["burp_version"], srv.hello
        # Ties the handshake to the JVM this test launched. peer_pid comes
        # from SO_PEERCRED -- the kernel fills it in and a peer cannot forge
        # it. The assertion this replaced, `peer_uid is not None`, could not
        # fail: _serve() sets peer_uid before the read loop and returns on a
        # uid mismatch, so state == "connected" already implies it.
        assert srv.peer_pid == proc.pid
        # The same number, self-reported in the hello frame. Weaker evidence
        # than the credential above, and worth checking separately: it is
        # what an operator sees, and it agreeing with the kernel is what
        # makes it trustworthy.
        assert srv.hello["pid"] == proc.pid

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


@pytest.mark.skipif(bool(bf._environment_missing()) and not bf.unbuilt(),
                    reason=f"missing: {', '.join(bf._environment_missing())}")
def test_burp_restart_returns_the_bridge_to_deny_all(tmp_path):
    """A Burp restart is a reconnect, not an outage -- and the reconnected
    extension knows nothing, because extensionData does not survive.

    Both halves are here. Killing Burp proves the bridge returns to DENY-ALL;
    only the second Burp dialling the same live BridgeServer proves the
    "reconnect, not an outage" half, which is this plan's headline claim and
    was otherwise exercised against fakes alone.
    """
    srv = server.BridgeServer(
        tmp_path / "hx.sock", engagement_id="e-restart",
        operator_halt=(oh := _operator_halt(tmp_path, "e-restart")))
    srv.start()
    proc = proc2 = None
    try:
        proc = bf.launch_burp(srv.socket_path, "e-restart", tmp_path / "first",
                              oh.sentinel_path)
        assert bf.wait_for(lambda: srv.state == "connected")
        srv.configure({"scope.include": ["https://a/*"]},
                      scope_sha256="abc", profile="production")
        assert srv.state == "configured"

        proc.kill()
        proc.wait(timeout=15)
        assert bf.wait_for(lambda: srv.state == "waiting", timeout=30), \
            "dropped connection must return the bridge to DENY-ALL"
        assert srv.config_epoch == 0

        # The restart. Same socket, same server object, never stopped.
        proc2 = bf.launch_burp(srv.socket_path, "e-restart", tmp_path / "second",
                               oh.sentinel_path)
        assert bf.wait_for(lambda: srv.state == "connected"), \
            "a restarted Burp must reconnect to the still-listening bridge"
        assert srv.peer_pid == proc2.pid, "the bridge is talking to the old JVM"
        # Still DENY-ALL: the reconnected extension carries nothing over,
        # because extensionData does not survive a Burp restart.
        assert srv.config_epoch == 0

        epoch = srv.configure({"scope.include": ["https://b/*"]},
                              scope_sha256="def", profile="production")
        assert epoch == 1, "a fresh extension numbers its first scope 1"
        assert srv.state == "configured"
    finally:
        # The first kill is inside the try for a reason -- it IS the restart
        # under test -- so on any earlier failure a 900 MB JVM would outlive
        # the run, once per debugging attempt. Two of them, now. Reaping an
        # already-reaped Popen is a no-op, so this is safe on the happy path.
        for p in (proc, proc2):
            if p:
                p.kill()
                p.wait(timeout=15)
        srv.stop()
```

- [ ] **Step 4: Build the extension and run the integration test**

```bash
cd extension && ./build.sh && cd ..
.venv/bin/pytest -m integration tests/integration -v
```

Expected: 2 passed in about 13 seconds. (This said 60-120s, which contradicted the same document's measured ~5s to hello, then 9s until round 1's restart test began launching a second Burp.)

If Burp never connects, read the launch output — the fixture merges stderr into stdout — and check the two failure modes established during research: the EULA prompt (needs `burp.eula` pre-accepted in `$BURP_HOME/.java/.userPrefs/burp/prefs.xml`) and the licence prompt (needs the bare newline the fixture already writes).

- [ ] **Step 5: Confirm the fast suite is still fast**

Run: `time .venv/bin/pytest -q`
Expected: PASS, 202 passed and 2 deselected in about 6 seconds — the integration tests excluded by `addopts`. What matters is that no JVM starts, not the exact count; the count moves every round. It has: this line said 188 when it was written, the suite was at 189 by the commit that finished the task, and 202 once round 1 added `tests/test_burp_fixture.py`.

- [ ] **Step 6: Commit**

```bash
git add tests/__init__.py tests/integration tests/test_burp_fixture.py pyproject.toml
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
