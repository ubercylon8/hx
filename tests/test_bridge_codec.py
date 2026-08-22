import json
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
