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

    The control request at the end is not ceremony. Burp is reached over a TCP
    port, and a port is whatever bound it first: an earlier draft of this
    fixture chose its ports by hand, and unrelated services on this machine
    answered `421` and a clean `200` while Burp was never involved and the
    probe file held nothing but `PROBE READY`. Nothing about a successful HTTP
    exchange proves the peer was Burp. A line in the probe file does, because
    only Burp's proxy can put one there.
    """
    if bf.probe_missing():
        pytest.skip(f"missing: {', '.join(bf.probe_missing())}")
    out = tmp_path / "probe.txt"
    target = TargetServer("127.0.0.1")
    target.start()
    proc = bf.launch_probe(tmp_path, out, extra_listener_port=0)
    try:
        assert bf.wait_for(lambda: out.exists() and "PROBE READY" in out.read_text()), \
            f"probe never started; burp.log: {tmp_path / 'burp.log'}"
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
    request was blocked; the assertion below exists to keep that fact from
    quietly ceasing to be true.
    """
    before = len(probe.target.hits)
    status = probe.through_proxy("/drop/secret")
    time.sleep(0.5)
    assert len(probe.target.hits) == before, (
        f"drop() did not prevent egress: the target received "
        f"{probe.target.hits[before:]}")
    assert any(l.startswith("DROPPED ") for l in probe.lines()), \
        "the handler never reached its drop branch; the test proved nothing"
    assert status == 200, (
        f"a dropped request now returns {status} to the client, not the 200 "
        "with Burp's own error page that was measured. That is a better answer "
        "than the measured one -- update docs/burp-proxy-measurements.md and "
        "this assertion together.")
