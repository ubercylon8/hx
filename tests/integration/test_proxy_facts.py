"""What Burp's proxy actually does, pinned so an upgrade cannot change it quietly.

These are MEASUREMENTS, not behaviour this project chose. Each one is a fact
about Burp 2026.7.3 that Plan 4's design rests on, and each test fails if a
future Burp answers differently -- which is the point. A design built on an
unmeasured assumption is how the previous branch shipped an auto-halt a peer
could disarm.

The prose record is `docs/burp-proxy-measurements.md`. These tests and that
document are one deliverable in two halves: the document says what Burp does
and the tests say it is still true. Q1's test reads the document back, so the
two cannot drift apart in silence.
"""
from __future__ import annotations

import re
import socket
import threading
import time
from pathlib import Path

import pytest

from tests.integration import burp_fixture as bf
from tests.integration.target_server import TargetServer

pytestmark = pytest.mark.integration

RECORD = Path(__file__).resolve().parents[2] / "docs" / "burp-proxy-measurements.md"

# The accessors on InterceptedRequest that might name the connection a request
# arrived on, in the order the probe writes them. `listenerPort` is in the list
# BECAUSE it does not exist: an accessor's absence is a measurement too, and one
# nobody would think to look for once the code is written around its absence.
ACCESSORS = ("listenerInterface", "listenerPort", "sourceIpAddress",
             "destinationIpAddress", "httpService")

# What Burp 2026.7.3 answered, classified. Three outcomes and not two: an
# accessor that EXISTS and THROWS is the trap here -- destinationIpAddress() is
# declared on the same InterceptedHttpMessage interface as listenerInterface(),
# compiles, and raises UnsupportedOperationException("Not yet implemented") the
# moment it is called. Code written against the interface's declared surface
# would reach for it as "a property of the connection" and find out at runtime.
MEASURED = {
    "listenerInterface": "present",
    "listenerPort": "absent",
    "sourceIpAddress": "present",
    "destinationIpAddress": "throws",
    "httpService": "present",
}

# What Burp answers the client whose request was DROPPED. Both halves are
# measured and each is load-bearing for a different reason.
#
# The STATUS is the finding: a delivered request returns 200 too, so a drop and
# a delivery are indistinguishable by status code and nothing may ever read the
# client's status as evidence that a request was blocked.
#
# The BYTE COUNT is what makes that finding checkable in the DOCUMENT. The
# document is the deliverable Task 5 acts from, and its whole Q3 client-response
# section could be deleted with this test still green -- reproduced -- because
# the document readback this file already had covered the accessor table and
# nothing else. A number this specific cannot survive in prose that no longer
# says what it is about. Burp's drop page is static: two drops of very different
# path lengths measured 1529 bytes each and it echoes nothing of the request, so
# this is a constant rather than a fingerprint of one URL.
DROPPED_STATUS = 200
DROPPED_BYTES = 1529

_FIELDS = ("id", "path", "status", "reqpath") + ACCESSORS
_SPLIT = re.compile(r" (?=(?:%s)=)" % "|".join(_FIELDS))


def fields(line: str) -> dict[str, str]:
    """The probe's `name=value` fields, split on the NAMES and not on whitespace.

    A value can contain spaces. `destinationIpAddress=<threw java.lang.
    UnsupportedOperationException: Not yet implemented>` is one field, and
    line.split() reads it as five -- losing the message, which is the only part
    of it that says anything about why the accessor cannot be used.
    """
    out: dict[str, str] = {}
    for chunk in _SPLIT.split(line):
        name, sep, value = chunk.partition("=")
        if sep and name in _FIELDS:
            out[name] = value
    return out


def classify(value: str) -> str:
    if value == "<absent>":
        return "absent"
    if value.startswith("<threw "):
        return "throws"
    return "present"


@pytest.fixture
def probe(tmp_path):
    """Real Burp running the probe extension, with a private home.

    Neither guard after `PROBE READY` is ceremony.

    The control request proves the peer is Burp. Burp is reached over a TCP
    port, and a port is whatever bound it first: an earlier draft of this
    fixture chose its ports by hand, and unrelated services on this machine
    answered `421` and a clean `200` while Burp was never involved and the
    probe file held nothing but `PROBE READY`. Nothing about a successful HTTP
    exchange proves the peer was Burp. A line in the probe file does, because
    only Burp's proxy can put one there.

    The loopback check proves the port is not open to the network. `listen_mode:
    loopback_only` goes into both listeners and was asserted in three places and
    checked by nothing: changing that one string to `all_interfaces` left this
    file reporting `3 passed in 38.03s` with `ss` showing the two listeners on
    `*:34777` and `*:38399` -- an open forward relay for as long as they run.

    A missing probe source FAILS rather than skips. It is a file this repository
    ships, not a prerequisite of this machine -- see bf.probe_source_missing().
    """
    gone = bf.probe_source_missing()
    if gone:
        pytest.fail(gone)
    if bf.probe_missing():
        pytest.skip(f"missing: {', '.join(bf.probe_missing())}")
    out = tmp_path / "probe.txt"
    target = TargetServer("127.0.0.1")
    target.start()
    proc = bf.launch_probe(tmp_path, out, extra_listener_port=0)
    try:
        assert bf.wait_for(lambda: out.exists() and "PROBE READY" in out.read_text()), \
            f"probe never started; burp.log: {tmp_path / 'burp.log'}"

        # Polled rather than read once: `PROBE READY` is written when the
        # extension loads and says nothing about when the listeners bound.
        # (Measured: all of them were already up at this point on every run
        # taken here, so the poll has never actually had to wait.)
        #
        # It costs one `ss` call on the happy path and the full 15 s on the
        # unhappy one -- waiting cannot turn a wildcard bind into a loopback
        # bind, so those seconds buy nothing there. Measured: these three
        # tests took 38.03 s before this check existed, 39.36 s with it, and
        # 81.28 s with the mutation in. That is the right way round for a
        # check that is only ever slow once it has already found something.
        violation: str | None = "the loopback check did not run"

        def on_loopback_only() -> bool:
            nonlocal violation
            violation = bf.not_loopback_only(proc.pid, bf.listener_ports(tmp_path))
            return violation is None

        assert bf.wait_for(on_loopback_only, 15), violation

        p = _Probe(out, target, bf.proxy_port(tmp_path),
                   bf.second_proxy_port(tmp_path))
        p.through_proxy("/health")
        assert bf.wait_for(lambda: any(l.startswith("REQ ") for l in p.lines()), 30), (
            f"a request to 127.0.0.1:{p.proxy_port} never reached the probe's "
            f"handler. Something answered on that port that is not this Burp -- "
            f"check `ss -tlnp | grep {p.proxy_port}`. burp.log: "
            f"{tmp_path / 'burp.log'}")
        yield p
    finally:
        proc.kill()
        proc.wait(timeout=30)
        target.stop()


class _Probe:
    def __init__(self, out: Path, target: TargetServer,
                 proxy_port: int, second_port: int):
        self.out, self.target = out, target
        self.proxy_port, self.second_port = proxy_port, second_port

    def lines(self) -> list[str]:
        return self.out.read_text().splitlines()

    def requests(self) -> list[dict[str, str]]:
        return [fields(l) for l in self.lines() if l.startswith("REQ ")]

    def responses(self) -> list[dict[str, str]]:
        return [fields(l) for l in self.lines() if l.startswith("RESP ")]

    def request_for(self, path: str) -> dict[str, str]:
        found = [r for r in self.requests() if r.get("path") == path]
        assert len(found) == 1, (
            f"expected exactly one request for {path}, got {len(found)}: "
            f"{self.lines()}")
        return found[0]

    def raw_through_proxy(self, path: str, port: int | None = None) -> bytes:
        """One proxied request, and the whole response as it came off the wire.

        `http.client` hands back a status and a decoded body. The byte count of
        the FULL response, head included, is the other half of what Q3 records,
        and no http.client API exposes it. Reading to EOF is safe for exactly
        one reason: the response this exists to measure carries
        `Connection: close`, which is Burp's own doing.
        """
        sock = socket.create_connection(("127.0.0.1", port or self.proxy_port),
                                        timeout=30)
        try:
            sock.sendall(f"GET {self.target.origin}{path} HTTP/1.1\r\n"
                         f"Host: {self.target.host}:{self.target.port}\r\n"
                         f"Connection: close\r\n\r\n".encode())
            chunks = []
            while chunk := sock.recv(65536):
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            sock.close()

    def through_proxy(self, path: str, port: int | None = None) -> int | None:
        """One request through Burp's proxy. None means the connection died."""
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", port or self.proxy_port,
                                          timeout=30)
        try:
            conn.request("GET", f"{self.target.origin}{path}")
            return conn.getresponse().status
        except (http.client.HTTPException, OSError):
            return None
        finally:
            conn.close()


def test_q1_whether_a_request_names_the_listener_it_arrived_on(probe):
    """Q1. Plan 4's operator/crawler split rests on this answer.

    Measured answer: YES. `listenerInterface()` returns `host:port` for the
    listener the request arrived on -- `127.0.0.1:42969` -- and two listeners in
    one Burp produce two different values for the same request. So the split can
    be a property of the CONNECTION, which is what spec s4 requires, and no
    second BridgeClient is needed.

    The two halves below are different claims and both are needed. The
    classification pins WHICH accessors Burp offers, so a future version that
    adds, removes or breaks one goes red here rather than in Task 5. The
    distinctness check pins that the value actually DISCRIMINATES: an accessor
    that existed and returned the same string for every listener would satisfy
    the first half completely and answer Q1 no.
    """
    assert probe.through_proxy("/api/orders") == 200
    assert probe.through_proxy("/account/logout", port=probe.second_port) == 200

    observed = {name: classify(probe.requests()[0][name]) for name in ACCESSORS}
    assert observed == MEASURED, (
        f"the accessors InterceptedRequest offers have changed: {observed} is "
        f"not the measured {MEASURED}. This is not necessarily a defect -- it is "
        "a new measurement. Update MEASURED and docs/burp-proxy-measurements.md "
        "together, and re-read Task 5's source attribution against the new set.")

    recorded = RECORD.read_text()
    for name, verdict in MEASURED.items():
        assert any(name in line and verdict in line
                   for line in recorded.splitlines()), (
            f"{name} is {verdict} on InterceptedRequest and no single line of "
            f"{RECORD.name} says so -- record what Burp offers before designing "
            "around what it does not")

    primary = probe.request_for("/api/orders")["listenerInterface"]
    second = probe.request_for("/account/logout")["listenerInterface"]
    assert primary != second, (
        f"both listeners report listenerInterface={primary!r}, so the accessor "
        "exists but tells the two apart from nothing. Q1's answer is NO and "
        "Task 5 needs the second-BridgeClient fallback.")
    assert primary.endswith(f":{probe.proxy_port}"), (primary, probe.proxy_port)
    assert second.endswith(f":{probe.second_port}"), (second, probe.second_port)


def test_q2_message_id_correlates_a_response_to_its_request(probe):
    """Q2. Capture pairs the two halves of an exchange by this id.

    Sequential requests would prove almost nothing: ids that merely count up
    match by accident when nothing overlaps. So two requests are put in flight
    at once against a target that answers the first one LAST, and the test
    requires the responses to arrive in the other order before it believes the
    pairing means anything.

    Measured answer: YES. Ids are assigned in request order and the response
    carries the id of ITS request, not of the exchange that finished first.
    """
    done: dict[str, int | None] = {}

    def go(name, path):
        done[name] = probe.through_proxy(path)

    slow = threading.Thread(target=go, args=("slow", "/slow?ms=2500"))
    fast = threading.Thread(target=go, args=("fast", "/api/orders"))
    slow.start()
    time.sleep(0.5)          # the slow exchange is already open
    fast.start()
    slow.join(60)
    fast.join(60)
    assert done == {"slow": 200, "fast": 200}, done

    reqs = {r["id"]: r for r in probe.requests()}
    resps = probe.responses()
    assert resps, "no response reached the handler"

    ids = {r["id"] for r in resps}
    assert ids <= set(reqs), (
        f"a response carried an id no request did: {ids - set(reqs)}. Capture "
        "cannot pair the halves of an exchange by messageId if this is false.")
    for resp in resps:
        assert resp["reqpath"] == reqs[resp["id"]]["path"], (
            f"messageId {resp['id']} is on a response whose initiating request "
            f"was {resp['reqpath']}, but the request with that id was "
            f"{reqs[resp['id']]['path']}. The id does not correlate.")

    order = [r["reqpath"] for r in resps]
    assert order.index("/api/orders") < order.index("/slow?ms=2500"), (
        f"the responses came back in request order ({order}), so nothing here "
        "was measured: the two exchanges never actually overlapped. Raise the "
        "/slow delay or check that the proxy is not serialising connections.")
    slow_id, fast_id = (probe.request_for("/slow?ms=2500")["id"],
                        probe.request_for("/api/orders")["id"])
    assert int(slow_id) < int(fast_id), (slow_id, fast_id)


def test_q3_drop_means_the_target_receives_nothing(probe):
    """Q3. The whole enforcement claim for this egress point.

    The target server is LISTENING throughout. A drop that merely fails to
    forward is indistinguishable from a connection error unless something on
    the far side can say it saw nothing -- which is why this asserts on the
    target's own log rather than on what the client got back.

    Measured answer: YES for egress, and the client-side half is a TRAP. Burp
    sends the dropping client `HTTP/1.1 200 OK` with its own HTML error page,
    so a dropped request is indistinguishable from a delivered one by status
    code alone. Nothing may ever read the client's status as evidence that a
    request was blocked.

    Three claims, and the third is about the DOCUMENT rather than about Burp.
    Egress is what the target's log settles. The status and byte count are what
    the client got. And `docs/burp-proxy-measurements.md` must still record
    both -- because that document, not this file, is what Task 5's implementer
    acts from, and the whole "client is told 200 OK" section could be deleted
    with every test here still green. Reading the two numbers back is the same
    mechanism Q1 uses for the accessor table, chosen over asserting them here
    alone for that reason: an assertion in this file keeps the FACT true, and
    only the readback keeps the DELIVERABLE true.
    """
    before = len(probe.target.hits)
    raw = probe.raw_through_proxy("/drop/secret")
    time.sleep(0.5)
    assert len(probe.target.hits) == before, (
        f"drop() did not prevent egress: the target received "
        f"{probe.target.hits[before:]}")
    assert any(l.startswith("DROPPED ") for l in probe.lines()), \
        "the handler never reached its drop branch; the test proved nothing"

    head = raw.split(b"\r\n", 1)[0]
    assert head.startswith(b"HTTP/"), (
        f"a dropped request no longer draws an HTTP response at all: {raw[:120]!r}")
    status = int(head.split()[1])
    assert (status, len(raw)) == (DROPPED_STATUS, DROPPED_BYTES), (
        f"a dropped request now draws {status} in {len(raw)} bytes from Burp, "
        f"not the measured {DROPPED_STATUS} in {DROPPED_BYTES}. If the status "
        "changed to something a client can tell apart from a delivery, that is a "
        "BETTER answer than the measured one and Plan 4 gets easier -- but it is "
        "a new measurement either way. Update DROPPED_STATUS/DROPPED_BYTES and "
        "docs/burp-proxy-measurements.md together. First line: "
        f"{head!r}")

    recorded = RECORD.read_text()
    assert any(str(DROPPED_BYTES) in line and str(DROPPED_STATUS) in line
               for line in recorded.splitlines()), (
        f"no single line of {RECORD.name} records that a dropped request draws "
        f"a {DROPPED_STATUS} of {DROPPED_BYTES} bytes. That is the most "
        "consequential finding in this task -- it is why a drop cannot be "
        "detected by status code -- and the document is what Task 5 is built "
        "from. Do not delete it from there to satisfy this assertion.")
    assert "indistinguishable" in recorded, (
        f"{RECORD.name} no longer says a dropped request is INDISTINGUISHABLE "
        "from a delivered one. The two numbers above can survive in a document "
        "that has stopped saying what they mean; this is the sentence that says "
        "it, and Task 5 reads the document rather than this test.")
