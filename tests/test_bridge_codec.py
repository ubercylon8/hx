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
