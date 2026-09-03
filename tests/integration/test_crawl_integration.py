# tests/integration/test_crawl_integration.py -- real Chromium, real extension
"""The crawler against a real Burp and a real Chromium.

MARKED `integration`: needs the Burp jar and the bundled browser, and takes
tens of seconds. Everything checkable without a browser is checked in the
unit suite; these are the three claims that cannot be.

LOOPBACK ONLY. `TargetServer` refuses any host outside 127.0.0.0/8 and that
refusal is load-bearing, not tidiness.

WHY A REAL CRAWL RATHER THAN `rig.browse`, in the first two tests. `rig.browse`
(the model `test_proxy_capture.py` follows for the operator/crawler split) is
a raw socket that hands bytes straight to a Burp listener -- it never asks
Chromium to decide whether a loopback destination should go through the
configured proxy at all, so it cannot see the ONE bug this task exists to
catch. Only `hx.crawl.run.crawl`, driving `hx.crawl.browser.Browser`'s real
`launch_argv`, puts that decision in the path. The third test is a Policy
question with no browser-specific claim in it, so it uses `rig.browse` like
every other proxy-split test in this suite -- see its own docstring.
"""
from __future__ import annotations

import dataclasses
import socket
import time

import pytest

from hx.crawl import frontier as frontier_mod
from hx.crawl import run as crawl_run_mod
from tests.integration.test_proxy_capture import status_of
from tests.integration.test_send_path import _refusal_from

pytestmark = pytest.mark.integration


def rows(rig, sql: str, args=()) -> list[dict]:
    return [dict(row) for row in rig.eng.db.execute(sql, args).fetchall()]


# A budget generous enough that nothing here truncates on a slow CI box, and
# small enough that a runaway crawl (a page that somehow keeps yielding new
# same-origin links) cannot turn a broken test into a hung one. Every seed
# below is one JSON endpoint with no links, so in the unbroken case the
# frontier empties itself after exactly one page and none of these numbers is
# ever actually reached.
_BUDGET = frontier_mod.Budget(max_pages=3, max_seconds=45, max_requests=50)


def _crawl(rig, *, seeds: list[str]) -> crawl_run_mod.CrawlSummary:
    return crawl_run_mod.crawl(seeds=seeds, proxy_port=rig.crawler_port,
                               budget=_BUDGET)


# ---------------------------------------------------------------------------
# 1. THE TEST THIS WHOLE PLAN TURNS ON.
# ---------------------------------------------------------------------------

def test_a_crawl_produces_exchanges_attributed_to_the_crawler(rig):
    """A real Chromium, launched with the real `browser.launch_argv`, must
    put its traffic through the crawler listener rather than around it.

    MEASURED 2026-09-02: a Chromium launched with `--proxy-server` alone and
    pointed at a loopback target sent ZERO connections to the proxy and
    reached it directly -- Chrome bypasses a configured proxy for loopback by
    default, and every target this suite is permitted to use is loopback.
    `browser.launch_argv` carries a second flag, `--proxy-bypass-list=<-
    loopback>`, that closes exactly this hole.

    MUTATION: delete that flag from `browser.launch_argv`
    (`sed -i '/proxy-bypass-list/d' src/hx/crawl/browser.py`). This test MUST
    go red.

    IT ASSERTS ON THE STORE, NEVER ON THE PAGE. A missing flag still renders
    the page perfectly -- Chromium reaches the target directly and gets the
    same bytes back -- so `summary.rendered == 1` or any assertion about the
    DOM would stay green under the mutation and prove nothing. What can only
    be true if the traffic actually crossed the crawler listener is a row in
    `exchange`, attributed to a `crawl` run, naming this request. Without the
    flag Chromium never dials the proxy at all, so no frame ever reaches
    `BridgeServer`, the sink is never called, and this settle times out --
    which is the failure this test is written to produce.

    WOULD THIS FAIL IF ITS CLAIM WERE FALSE? Under the mutation above,
    Chromium still renders `/health` (a direct loopback connection succeeds
    identically to a proxied one against this target), so `crawl()` still
    returns a normal-looking `CrawlSummary` with one rendered page. The
    settle below is the only thing that can tell the two situations apart,
    and its own failure message says why -- see `Rig.settle`.
    """
    assert rig.configure() == 1

    seed = f"{rig.target.origin}/health"
    summary = _crawl(rig, seeds=[seed])
    assert summary.pages == 1, (
        f"the crawl visited {summary.pages} page(s) for one seed with no "
        f"links; something about the frontier or the seed URL is wrong "
        f"before this test can say anything about attribution: {summary}")

    rig.settle(
        lambda: rows(rig, "SELECT e.id FROM exchange e"
                          " JOIN run r ON e.run_id = r.id"
                          " WHERE r.kind = 'crawl'"),
        "an exchange row attributed to a crawl run -- meaning Chromium's "
        "request for the seed above actually crossed the crawler proxy "
        "listener rather than going around it")

    crawler_rows = rows(
        rig, "SELECT e.*, r.kind AS run_kind FROM exchange e"
             " JOIN run r ON e.run_id = r.id WHERE r.kind = 'crawl'")
    urls = {row["url"] for row in crawler_rows}
    assert seed in urls, (
        f"a crawl run recorded exchanges, but none of them named the seed "
        f"{seed!r}: {urls}. The crawler listener is carrying SOME traffic; "
        f"this crawl's own request is not it")
    for row in crawler_rows:
        # 'proxy', not 'send' -- this came through ProxyGate, not the bridge
        # send handler. Every row here should agree, since this test drove
        # exactly one browser through exactly one listener.
        assert row["via"] == "proxy", row
        assert row["run_id"] in {r["id"] for r in
                                 rows(rig, "SELECT id FROM run"
                                          " WHERE kind='crawl'")}

    seed_row = next(row for row in crawler_rows if row["url"] == seed)
    assert seed_row["method"] == "GET"
    assert seed_row["outcome"] == "ok"
    assert seed_row["status"] == 200


# ---------------------------------------------------------------------------
# 2. An out-of-scope destination is dropped and the drop is recorded.
# ---------------------------------------------------------------------------

def test_an_out_of_scope_destination_is_dropped_and_recorded(rig):
    """`TargetServer` binds the in-scope target on 127.0.0.1 and the
    out-of-scope one (`rig.offside`) on 127.0.0.2 -- BOTH LOOPBACK, so this
    shares test 1's blind spot: if Chromium bypassed the crawler's proxy for
    loopback, it would reach 127.0.0.2 DIRECTLY, and "no exchange was
    recorded for it" would be true for entirely the wrong reason -- a bypass,
    not a refusal.

    So the assertion is the PRESENCE of a denial row and the offside
    target's log staying flat, never the absence of an exchange on its own.

    MUTATION: remove the `if (source == Source.CRAWLER)` branch from
    `ProxyGate.decide` (`extension/src/hx/proxy/ProxyGate.java`). Must go red.

    THREE CONTROLS, the same shape `test_proxy_capture.py`'s out-of-scope
    test uses and for the same reason -- "the log did not move" is satisfied
    by a great many things that are not enforcement:

      - the offside target is hit DIRECTLY first, so its log is proven able
        to move at all;
      - an in-scope crawl through the SAME listener is proven to deliver,
        so the proxy path is known to be carrying traffic when the refusal
        is measured;
      - the denial ROW is asserted, so "nothing arrived" (a broken crawl, a
        dead listener) is told apart from "hx refused it".

    A SECOND MEASUREMENT LIVES BELOW THE FIRST, and it is not decoration --
    it is the only half of this test the named mutation actually reaches.
    MEASURED: with the CRAWLER branch removed, a request from that listener
    falls to `Policy.decideScopeOnly` -- the OPERATOR's question -- which
    asks about scope and stops. For a destination `scope.include` never
    named at all, `decideScopeOnly` denies it exactly as `decideCrawl` would
    have (both are `checkScope` underneath), so the out-of-scope half above
    is UNCHANGED by this mutation and stays green: confirmed by running it
    against the mutated jar before writing this paragraph. `dangerous.path`
    is what `decideScopeOnly` never asks and `decideCrawl` does, so a
    request that is IN scope and ALSO matches a dangerous pattern is what
    the mutation actually flips from denied to delivered -- proven the same
    way, against the same jar: the out-of-scope half stayed green and the
    dangerous-path half below went red, naming a hit at `/account/logout`.
    """
    assert rig.configure() == 1

    # Control 1: the offside log moves when something reaches it directly.
    direct = socket.create_connection((rig.offside.host, rig.offside.port),
                                      timeout=10)
    try:
        direct.sendall(b"GET /health HTTP/1.1\r\n"
                       b"Host: " + rig.offside.host.encode() + b"\r\n"
                       b"Connection: close\r\n\r\n")
        while direct.recv(65536):
            pass
    finally:
        direct.close()
    assert [(h.method, h.path) for h in rig.offside.hits] == [("GET", "/health")]

    # Control 2: the crawler listener is carrying real browser traffic right
    # now, against the in-scope target.
    control = _crawl(rig, seeds=[f"{rig.target.origin}/health"])
    assert control.pages == 1, control
    rig.settle(
        lambda: rows(rig, "SELECT id FROM exchange WHERE url=?",
                    (f"{rig.target.origin}/health",)),
        "the in-scope control's exchange row -- without this, a refusal "
        "below would be satisfied by a crawler that is not working at all")

    # The measurement. 127.0.0.2 is out of scope -- the engagement's
    # scope.include is the 127.0.0.1 target's origin and nothing else -- and
    # it is LISTENING throughout, so a refusal that merely failed to deliver
    # is separable from one that actively kept the bytes off it.
    before = len(rig.offside.hits)
    seed = f"{rig.offside.origin}/health"
    summary = _crawl(rig, seeds=[seed])
    assert summary.pages == 1, summary

    rig.settle(
        lambda: rows(rig, "SELECT id FROM denial"
                          " WHERE via='proxy' AND kind='scope'"),
        "the out-of-scope crawler denial")
    # Settled, then given the same window again: the denial arriving proves
    # the extension decided, not that the bytes stayed put -- a request that
    # leaked around the gate would reach a loopback server well inside this.
    time.sleep(0.5)

    assert len(rig.offside.hits) == before, (
        "THE VERDICT WAS NOT HONOURED, or Chromium never asked for one: the "
        f"out-of-scope target received "
        f"{[(h.method, h.path) for h in rig.offside.hits[before:]]}. Either "
        "the crawler's `--proxy-bypass-list=<-loopback>` flag is doing "
        "nothing for this destination, or the extension refused this "
        "request and the bytes went out anyway.")

    # THE SECOND MEASUREMENT. In scope, on the SAME listener, matching the
    # dangerous.path denylist -- the rule decideScopeOnly never asks, so this
    # is what actually moves under the mutation named above.
    dangerous_path = "/account/logout"
    dangerous_before = len(rig.target.hits_for(dangerous_path))
    dangerous = _crawl(rig, seeds=[f"{rig.target.origin}{dangerous_path}"])
    assert dangerous.pages == 1, dangerous

    rig.settle(
        lambda: rows(rig, "SELECT id FROM denial"
                          " WHERE via='proxy' AND kind='dangerous'"),
        "the crawler's dangerous-path denial")
    time.sleep(0.5)

    assert len(rig.target.hits_for(dangerous_path)) == dangerous_before, (
        "a dangerous-path destination reached the target through the "
        f"crawler listener: {dangerous_path} took "
        f"{len(rig.target.hits_for(dangerous_path)) - dangerous_before} "
        "more hit(s). This is the half of the test that the CRAWLER-branch "
        "mutation actually moves -- see the docstring.")

    dangerous_denial = rows(
        rig, "SELECT * FROM denial WHERE via='proxy' AND kind='dangerous'")[0]
    assert dangerous_denial["url"] == f"{rig.target.origin}{dangerous_path}"

    denial = rows(rig, "SELECT * FROM denial"
                       " WHERE via='proxy' AND kind='scope'")[0]
    assert denial["method"] == "GET"
    assert denial["url"] == seed
    kinds = {row["id"]: row["kind"] for row in rows(rig, "SELECT id, kind FROM run")}
    assert kinds[denial["run_id"]] == "crawl", (
        "the refused request was attributed to a run of kind "
        f"{kinds.get(denial['run_id'])!r}, not 'crawl' -- the denial is real "
        "but filed under the wrong driver")

    # No exchange for the offside seed either, which is the complementary
    # half of the same fact -- not the primary claim (see the docstring
    # above for why "absent" is not load-bearing on its own here).
    assert rows(rig, "SELECT id FROM exchange WHERE url=?", (seed,)) == []


# ---------------------------------------------------------------------------
# 3. render.allow enforces for the crawler and not for the send path.
# ---------------------------------------------------------------------------

def test_render_allow_changes_the_outcome_for_the_crawler_only(rig):
    """Task 1 end to end. `Policy.decideCrawl` consults `render.allow` after
    `scope.include`/`scope.exclude`; `Policy.decideBeforeGate` -- the path
    `Sender` sends every CHECK's probe through -- calls the same shared
    `beforeGate` with `renderAllow=false` and never looks at it.

    NO BROWSER-SPECIFIC CLAIM LIVES HERE, unlike the two tests above: this is
    a question about which of two Java methods a listener calls, and
    `rig.browse` -- a raw socket handed straight to a Burp listener, the same
    shape `test_proxy_capture.py`'s operator/crawler split test uses -- puts
    that decision in the path just as well as a real Chromium would, at a
    fraction of the cost. `render.allow` is set into the engagement's real
    config and travels to the extension over the real `configure` frame
    either way.

    MUTATION: change `Policy.decideBeforeGate` to call
    `beforeGate(req, auth, true)` instead of `false`
    (`extension/src/hx/policy/Policy.java`). Must go red on the SECOND half
    -- the send-path probe below would then be silently authorised by
    render.allow too, which is exactly the widening s4's send/crawl split
    exists to prevent: a rendering concession is not a licence for a security
    check to issue a probe.
    """
    rig.eng.config = dataclasses.replace(
        rig.eng.config, render_allow=[f"{rig.offside.origin}/*"])
    assert rig.configure() == 1

    # THE CRAWLER HALF: render.allow authorises a destination scope.include
    # never named.
    crawler_resp = rig.browse("GET", "/health", to=rig.offside,
                              port=rig.crawler_port)
    assert status_of(crawler_resp) == 200, (
        "the crawler listener refused a destination named in render.allow: "
        f"{status_of(crawler_resp)}")
    assert rig.offside.hits_for("/health"), (
        "render.allow authorised the request on this side, and the offside "
        "target never saw it -- a client-side 200 is not evidence of "
        "delivery (see DROP_LOOKS_LIKE); read its log instead")
    rig.settle(
        lambda: rows(rig, "SELECT e.id FROM exchange e"
                          " JOIN run r ON e.run_id = r.id"
                          " WHERE r.kind='crawl' AND e.url=?",
                    (f"{rig.offside.origin}/health",)),
        "the crawler's render.allow exchange row")

    # THE SEND-PATH HALF: same render.allow in force, same destination, and
    # this route must refuse it exactly as if render.allow did not exist --
    # `send_unguarded` drops only THIS side's own refusals (see its
    # docstring), so a refusal that comes back proves the JVM decided, not
    # this harness's bookkeeping.
    before = len(rig.offside.hits)
    refusal = _refusal_from(rig.send_unguarded, "GET", "/health",
                            to=rig.offside)
    assert refusal is not None, (
        "a send-path probe to a render.allow-only destination was ALLOWED. "
        "render.allow is a concession to RENDERING (Task 1's own words) and "
        "must never widen what a security CHECK may send -- Sender calls "
        "Policy.decideBeforeGate, which is not supposed to consult it at all")
    assert refusal.error_class == "scope_denied", refusal
    assert len(rig.offside.hits) == before, (
        "the send path was refused on this side and the offside target's "
        f"log moved anyway: {rig.offside.hits[before:]}")
