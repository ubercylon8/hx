"""`hx.crawl.cdp`, driven by a real child process over real pipes.

NO BROWSER. The peer is a few lines of Python speaking CDP framing, which
is the whole point: the framing, the id correlation and the fd inheritance
are what break, and a `unittest.mock` double would exercise none of them.
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

from hx.crawl import cdp

PEER = r'''
import json, os, sys
buf = b""
deferred = None
while True:
    chunk = os.read(3, 65536)
    if not chunk:
        break
    buf += chunk
    while b"\0" in buf:
        raw, buf = buf.split(b"\0", 1)
        msg = json.loads(raw)
        # Flush what we owe BEFORE answering the new message, so an older
        # reply reaches the pipe ahead of a newer one.
        if deferred is not None:
            os.write(4, json.dumps(
                {"id": deferred, "result": {"deferred": True}}).encode() + b"\0")
            deferred = None
        if msg["method"] == "Peer.deferred":
            deferred = msg["id"]
            continue
        if msg["method"] == "Peer.emitEvent":
            os.write(4, json.dumps(
                {"method": "Peer.happened", "params": {"n": 1}}).encode() + b"\0")
        if msg["method"] == "Peer.fail":
            err = {"code": -32000, "message": "peer refused"}
            os.write(4, json.dumps(
                {"id": msg["id"], "error": err}).encode() + b"\0")
            continue
        if msg["method"] == "Peer.silent":
            continue
        if msg["method"] == "Peer.garbled":
            os.write(4, b"{not json\0")
            reply = {"id": msg["id"], "result": {"echo": "after garbage"}}
            os.write(4, json.dumps(reply).encode() + b"\0")
            continue
        reply = {"id": msg["id"], "result": {"echo": msg.get("params", {})}}
        os.write(4, json.dumps(reply).encode() + b"\0")
'''


def _peer() -> tuple[cdp.Connection, subprocess.Popen]:
    """A child speaking CDP on fds 3 and 4, wired exactly as Chromium is."""
    to_child_r, to_child_w = os.pipe()
    from_child_r, from_child_w = os.pipe()

    def fixup():
        os.dup2(to_child_r, 3)
        os.dup2(from_child_w, 4)

    proc = subprocess.Popen([sys.executable, "-c", PEER],
                            preexec_fn=fixup, pass_fds=(3, 4), close_fds=True)
    os.close(to_child_r)
    os.close(from_child_w)
    return cdp.Connection(read_fd=from_child_r, write_fd=to_child_w), proc


def test_a_call_gets_its_own_reply():
    conn, proc = _peer()
    try:
        assert conn.call("Peer.echo", {"x": 7}) == {"echo": {"x": 7}}
    finally:
        conn.close()
        proc.kill()


def test_replies_are_matched_by_id_not_by_arrival_order():
    """THE CORRELATION TEST, and the fixture is the whole of it.

    `Peer.deferred` leaves the peer owing a reply to id=1. That reply is
    flushed to the pipe immediately BEFORE the reply to id=2, so two replies
    arrive out of order and the transport must hand each caller its own.

    MUTATION: in `call`, return the first message carrying any `id` rather
    than the one matching `msg_id`. This test must go red -- id=2's caller
    would receive `{"deferred": True}`.

    An earlier draft of this test used a peer that never replied at all, so
    only one reply ever existed and the mutation above still passed it. That
    is why the fixture is shaped this way and not more simply.
    """
    conn, proc = _peer()
    try:
        with pytest.raises(cdp.CdpTimeout):
            conn.call("Peer.deferred", timeout=0.3)
        assert conn.call("Peer.echo", {"b": 2}) == {"echo": {"b": 2}}
    finally:
        conn.close()
        proc.kill()


def test_a_protocol_error_is_raised_and_not_returned_as_a_result():
    """MUTATION: return `msg` instead of raising when it carries `error`.
    Must go red -- a caller would read a CDP failure as a successful result.
    """
    conn, proc = _peer()
    try:
        with pytest.raises(cdp.CdpError, match="peer refused"):
            conn.call("Peer.fail")
    finally:
        conn.close()
        proc.kill()


def test_a_silent_peer_times_out_rather_than_blocking_forever():
    """MUTATION: drop the deadline from the read loop. Must hang, then red.

    The timeout is what stops one wedged navigation consuming the whole
    crawl budget -- spec S5's per-page cap depends on this raising.
    """
    conn, proc = _peer()
    try:
        with pytest.raises(cdp.CdpTimeout):
            conn.call("Peer.silent", timeout=0.3)
    finally:
        conn.close()
        proc.kill()


def test_events_arriving_during_a_call_are_buffered_not_discarded():
    """Events and replies share one pipe. An event that arrives while a call
    is outstanding must survive to be drained.

    MUTATION: in the read loop, `continue` past any message with no `id`
    instead of appending it to `self.events`. Must go red -- and the crawl
    would silently lose every Network event, reporting pages that requested
    nothing.
    """
    conn, proc = _peer()
    try:
        conn.call("Peer.emitEvent")
        events = conn.drain(timeout=1.0)
        assert any(e["method"] == "Peer.happened" for e in events)
    finally:
        conn.close()
        proc.kill()


def test_a_dead_peer_raises_closed_rather_than_hanging():
    """MUTATION: in `_pump`, replace `if not chunk: raise CdpClosed(...)`
    with `if not chunk: return`. Must go red.

    The peer closes only its OUTPUT (fd 4) and then blocks, keeping its
    INPUT (fd 3) open. That forces the failure through `_pump`'s read loop:
    `_write` still succeeds (a reader is still attached), so the only way
    this call can fail is a zero-length read on our end. A peer killed
    outright would instead break the write with EPIPE and raise CdpClosed
    from `_write`, unaffected by this mutation -- passing this test for the
    wrong reason regardless of what `_pump` does with a zero-length read.

    Under the mutation, `_pump` returns instead of raising, `call` loops
    back around, `_pump` reads EOF again (a closed pipe is always
    select()-ready), and this repeats until the call's own deadline fires
    CdpTimeout -- a *different* exception than the CdpClosed asserted below,
    so the mutation still turns this red rather than slipping through a
    tuple of acceptable exceptions.
    """
    to_child_r, to_child_w = os.pipe()
    from_child_r, from_child_w = os.pipe()

    def fixup():
        os.dup2(to_child_r, 3)
        os.dup2(from_child_w, 4)

    proc = subprocess.Popen(
        [sys.executable, "-c", "import os, time; os.close(4); time.sleep(5)"],
        preexec_fn=fixup, pass_fds=(3, 4), close_fds=True,
    )
    os.close(to_child_r)
    os.close(from_child_w)
    conn = cdp.Connection(read_fd=from_child_r, write_fd=to_child_w)
    try:
        with pytest.raises(cdp.CdpClosed):
            conn.call("Peer.echo", timeout=2.0)
    finally:
        conn.close()
        proc.kill()
        proc.wait()


def test_a_fully_dead_peer_fails_the_write_not_the_read():
    """MUTATION: in `_write`, swallow the `OSError` and `return` instead of
    raising `CdpClosed`. Must go red -- with the write silently dropped,
    `call` proceeds into `_pump`, finds nothing to read (the read pipe's
    write end is deliberately held open below, so there is no EOF to catch
    it either), and instead of failing closed it just burns its timeout and
    raises `CdpTimeout` -- a different exception than the `CdpClosed`
    asserted here.

    COMPANION to `test_a_dead_peer_raises_closed_rather_than_hanging`, and
    deliberately a SEPARATE fixture rather than one shared with it -- and
    deliberately NOT a real child process either, unlike every other test in
    this file. A "kill the peer outright" child (the brief's original
    fixture, and my first attempt at this one) makes the mutation
    UNOBSERVABLE: with both of the peer's fds gone, a silently-swallowed
    write failure is immediately backstopped by `_pump`'s own (unmutated,
    correct) read-EOF check, which also raises `CdpClosed` -- so the test
    goes green for the wrong reason, the very failure this task exists to
    catch. A "close only fd 3, then sleep" child fixes that in principle but
    is racy in practice: nothing guarantees the child has closed its read
    end before this test's first `os.write` runs, and a write that lands
    before the close just sits unread in the kernel buffer forever, timing
    out regardless of whether `_write` is correct or mutated -- confirmed
    empirically, the "corrected" child fixture still failed on CORRECT code.
    Two bare pipes, entirely in this process, are what make each end's
    state deterministic: no fork, no exec, no race to lose.

    `to_peer_w` has its only reader closed before `Connection` ever touches
    it, so `_write`'s `os.write` is guaranteed EPIPE. `from_peer_r`'s writer
    (`from_peer_w`) is held open and never written to, so a read on it can
    only block, never see EOF -- there is no other way this call can end
    except through `_write`'s own error handling.
    """
    to_peer_r, to_peer_w = os.pipe()
    os.close(to_peer_r)
    from_peer_r, from_peer_w = os.pipe()

    conn = cdp.Connection(read_fd=from_peer_r, write_fd=to_peer_w)
    try:
        with pytest.raises(cdp.CdpClosed):
            conn.call("Peer.echo", timeout=2.0)
    finally:
        conn.close()
        os.close(from_peer_w)


def test_a_malformed_frame_is_dropped_not_fatal():
    """CONTROLLER RULING: `_pump`'s `except ValueError: continue` stays, even
    though dropping an unparseable frame looks like it violates this
    project's fail-closed rule as literally stated. It does not: fail-closed
    governs decisions that could permit egress or authorise an action --
    never allow what you could not verify. A garbled frame on a local pipe
    from a browser we launched authorises nothing. Raising would let one
    malformed frame end an entire crawl. Dropping is the safe direction on
    both branches: a lost reply surfaces as the caller's own `CdpTimeout`,
    which is loud; a lost event makes a page look like it requested less
    than it did, which the crawler's page classifier reads as less yield --
    i.e. it under-claims coverage, the direction spec Sec 12 explicitly
    prefers.

    MUTATION: re-raise instead of `continue` in that except block. Must go
    red -- the call would die on the garbage frame instead of returning the
    good reply that follows it on the same pipe.
    """
    conn, proc = _peer()
    try:
        assert conn.call("Peer.garbled") == {"echo": "after garbage"}
    finally:
        conn.close()
        proc.kill()
