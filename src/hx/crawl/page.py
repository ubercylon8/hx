# src/hx/crawl/page.py -- one page, in full
"""Navigate one page, wait for it to settle, harvest, and judge it.

THE JUDGEMENT IS THE POINT. S12: a report that cannot distinguish "tested,
clean" from "never reached" is worse than no report. Applied to a crawl, the
failure is precise -- the proxy drops an out-of-scope bundle, the SPA never
boots, and the crawler records a clean visit to an application it never
rendered. Only the browser can see this: the store knows a request was
denied, it does not know whose render the denial broke.

`classify` is therefore a pure function over CDP events, so the judgement
can be tested without a browser and read without running anything.

SESSION REQUIRED (Ruling 9, measured 2026-09-02): `--remote-debugging-pipe`
gives a BROWSER-level CDP connection. `Page`, `Network` and `DOM` do not
exist on it -- `Page.enable` came back "wasn't found" without a page-target
session attached. `visit` therefore takes a required `session_id` and every
domain call carries it; `Browser.__enter__` (`hx.crawl.browser`) is what
creates that session, once, for the browser's whole lifetime.
"""
from __future__ import annotations

import time
from html.parser import HTMLParser
from typing import NamedTuple
from urllib.parse import urljoin, urlsplit

from hx.crawl import cdp
from hx.crawl.frontier import normalise, origin_of

#: Attributes that carry a page address. `form action` is here because it is
#: an address we may GET; SUBMITTING a form is S9's deferred policy and this
#: build does not do it.
_LINK_ATTRS = {"a": "href", "area": "href", "iframe": "src", "form": "action"}


class PageResult(NamedTuple):
    state: str                       # rendered | degraded | failed
    requests: int
    dropped_hosts: tuple[str, ...]
    in_scope_failures: tuple[str, ...]
    capped: bool
    load_errors: tuple[str, ...] = ()


#: Console text meaning A RESOURCE THIS PAGE NEEDED DID NOT LOAD.
#:
#: NARROW ON PURPOSE. A page under test logs errors all day -- a failed
#: analytics beacon, a caught exception, a deprecation warning -- and none of
#: those mean the application did not come up. These do: each is the browser
#: refusing to EXECUTE something the document asked for.
#:
#: MEASURED 2026-09-03 against OWASP Juice Shop through this crawler's own
#: Burp. Its Express server mishandles the absolute-form request line every
#: client sends to a proxy (RFC 9112 s3.2.2), so `GET http://host/chunk.js`
#: fell through to the SPA catch-all and returned `index.html` with
#: `Content-Type: text/html`. Chrome enforces strict MIME checking on module
#: scripts, refused all four, and Angular never bootstrapped -- 5 requests
#: instead of 41, and NOT ONE of the parameterised API endpoints a scan
#: exists to probe.
#:
#: The crawl reported that page `rendered`, with no truncation, because
#: nothing was dropped and no budget was hit. Every S12 mechanism in this
#: file stayed silent while the page loaded 0.4% of its application. The
#: browser had said so in plain English the whole time, on a domain nobody
#: had enabled.
#: EVERY ONE IS THE BROWSER REFUSING TO EXECUTE OR APPLY SOMETHING, which is
#: the semantic that separates "the app did not come up" from "a fetch
#: failed". `"failed to load resource"` was in this tuple for one review
#: round and is deliberately NOT: it is Chrome's generic message for ANY
#: failed subresource -- a 404 favicon, a blocked beacon, a missing font --
#: so it made the very example this file's own comment gives as NOT a load
#: failure into one. A marker list that contradicts the paragraph above it is
#: worse than a short list.
_LOAD_FAILURE_MARKERS = (
    "failed to load module script",
    "refused to execute script",
    "refused to apply style",
    "was blocked due to mime type",
)


def load_failures(events: list[dict]) -> tuple[str, ...]:
    """What the PAGE ITSELF reported it could not load, deduplicated.

    Reads `Log.entryAdded` -- the shape measured above is
    `{"entry": {"source", "level", "text", "url"}}`. Only `level == "error"`
    counts: a warning is the browser telling you about something it went
    ahead and did.
    """
    out: list[str] = []
    for e in events:
        if e.get("method") != "Log.entryAdded":
            continue
        entry = e.get("params", {}).get("entry", {})
        if entry.get("level") != "error":
            continue
        text = (entry.get("text") or "").lower()
        if not any(m in text for m in _LOAD_FAILURE_MARKERS):
            continue
        what = entry.get("url") or entry.get("text") or ""
        if what and what not in out:
            out.append(what)
    return tuple(out)


class _Links(HTMLParser):
    """Tolerant by construction: a page under test is attacker-influenced
    input, and one malformed document must not end a crawl."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: list[str] = []
        self.base: str | None = None

    def handle_starttag(self, tag, attrs) -> None:
        d = dict(attrs)
        if tag == "base" and d.get("href"):
            self.base = d["href"]
            return
        attr = _LINK_ATTRS.get(tag)
        if attr and d.get(attr):
            self.found.append(d[attr])


def harvest(html: str, base_url: str) -> list[str]:
    """Absolute URLs a page points at, in document order, deduplicated.

    Read from the SETTLED DOM rather than the served HTML, which is the whole
    reason a browser is involved: verified 2026-09-02 that a JS-injected
    anchor appears in the rendered DOM and not in the source.
    """
    parser = _Links()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        # Whatever it parsed before giving up is still real. Raising here
        # would let one broken page end a crawl.
        pass
    base = urljoin(base_url, parser.base) if parser.base else base_url
    out: list[str] = []
    seen: set[str] = set()
    for raw in parser.found:
        absolute = urljoin(base, raw.strip())
        if absolute not in seen:
            seen.add(absolute)
            out.append(absolute)
    return out


def classify(events: list[dict], *, page_origins: set[str],
             harvested: int, capped: bool = False) -> PageResult:
    """What this page tells us, and what it does not.

    A failed subresource is classified by ORIGIN, and the two answers are
    different facts: an out-of-scope failure is one hx dropped, an in-scope
    failure is the target itself failing. Reporting them as one would send an
    operator to put their own application's host into `render_allow`.

    `page_origins` IS SEED ORIGINS, NOT SCOPE -- read that literally, not as
    a simplification. Spec §6 describes this split as made "by re-running the
    scope predicate"; spec §7 forbids a second Python scope matcher (`there
    is no Python scope matcher in this repo today ... a second matcher is a
    second answer`). `hx.crawl.run.crawl` resolves that by building
    `page_origins` from the seed URLs' own origins, which is a narrower
    question than scope and can disagree with it in exactly one direction:
    an engagement whose scope covers a second origin that was NEVER SEEDED
    (say scope allows `api.app.test` but only `app.test` was given as a
    seed) will have a target-side failure on that unseeded-but-in-scope
    origin classified here as an out-of-scope drop, because this function has
    no way to know the origin is in scope -- it only knows it was not seeded.
    That host then lands in `dropped_hosts` (the list `render_allow` is
    pasted from) instead of `in_scope_failures`, and nothing here contradicts
    it. The JVM's own `denial` table is the authoritative record of what was
    actually dropped by policy (§6: "cross-checkable against the denial
    rows, which remain authoritative") -- an operator relying on
    `dropped_hosts` alone should confirm against those rows before treating
    a host as policy-dropped, precisely because this predicate can be wrong
    in that one direction. It is never wrong the other way: an origin this
    predicate calls in-scope really was seeded, so `in_scope_failures` never
    contains a host hx would have dropped.
    """
    urls: dict[str, str] = {}
    failed: set[str] = set()
    answered: set[str] = set()
    first_seen: str | None = None
    typed_document: str | None = None

    for e in events:
        params = e.get("params", {})
        rid = params.get("requestId")
        if e.get("method") == "Network.requestWillBeSent":
            url = params.get("request", {}).get("url", "")
            urls[rid] = url
            if first_seen is None:
                first_seen = rid
            # F4 (whole-branch review, re-diagnosis of a previously-logged
            # favicon race): the page session is REUSED for every URL in the
            # crawl, and `visit`'s `conn.drain(timeout=0.0)` before
            # navigation only clears events that have ALREADY ARRIVED -- a
            # trailing event from the PREVIOUS page can still be in flight
            # and be the first thing this page's event list sees. Judging
            # "the document" by arrival order then risks taking page N-1's
            # request as page N's document, and if that stale request
            # happened to succeed while the real document failed, this page
            # OVER-CLAIMS -- reported `rendered` for a page that never
            # loaded, which is the direction §12 calls unsurvivable.
            # Chromium sets `type` on `Network.requestWillBeSent` and marks
            # exactly the navigation request `"Document"`, so that field
            # identifies the real document regardless of arrival order.
            if typed_document is None and params.get("type") == "Document":
                typed_document = rid
        elif e.get("method") == "Network.loadingFailed":
            failed.add(rid)
        elif e.get("method") == "Network.responseReceived":
            answered.add(rid)

    # PREFER THE TYPED DOCUMENT; FALL BACK TO FIRST ARRIVAL. A synthetic or
    # truncated event stream (as every test in this file constructs, and as
    # a capped/aborted real page may produce) may carry no `type` field at
    # all -- first-arrival is still the best available signal then, exactly
    # as it was before this fix, so a stream with no typed event classifies
    # exactly as it always did.
    document = typed_document if typed_document is not None else first_seen

    # A DROP IS A FAILURE WITH NO RESPONSE (Ruling 11, measured 2026-09-02):
    # a proxy that closes without answering produces `loadingFailed`
    # (net::ERR_EMPTY_RESPONSE) and NO `responseReceived`, while a resource
    # that was served and then broke mid-body produces BOTH. Treating the
    # sets as disjoint would put a served-then-broken third party into
    # `dropped_hosts` -- and that list is what an operator pastes into
    # `render_allow`, so they would widen scope to fix something nothing
    # blocked. It would also report a document that loaded and then had a
    # trailing body error as `failed`, when it was in fact received and
    # harvested.
    dropped_candidates = failed - answered

    dropped: set[str] = set()
    in_scope_failures: list[str] = []
    for rid in dropped_candidates:
        url = urls.get(rid, "")
        if origin_of(url) in page_origins:
            in_scope_failures.append(url)
        else:
            host = urlsplit(url).hostname
            if host:
                dropped.add(host)

    failures = load_failures(events)

    if document is None or document in dropped_candidates:
        state = "failed"
    elif failures:
        # THE PAGE SAID SO ITSELF, and it outranks `yielded` deliberately.
        # A document that fetched three links and then could not execute its
        # own main module has not rendered the application, and counting the
        # three as yield would report it `rendered`. Measured against Juice
        # Shop: 5 requests, no drops, no budget hit, four refused module
        # scripts -- and a confident `rendered` for a page that loaded 0.4%
        # of its app.
        #
        # This can over-fire: a broken analytics script on an otherwise
        # healthy page lands here. That is a FALSE DEGRADATION and it is the
        # direction this file already errs in on purpose -- S12's asymmetry
        # is that under-claiming coverage is survivable and over-claiming is
        # not. `_LOAD_FAILURE_MARKERS` is kept narrow so it stays rare.
        state = "degraded"
    else:
        # YIELD is links OR in-scope requests beyond the document itself.
        # The second half is not decoration: S9's measured 65-requests result
        # came from a page's own fetch calls, and a page that produced only
        # XHR has been reached.
        own = sum(1 for rid, url in urls.items()
                  if rid != document and origin_of(url) in page_origins)
        yielded = harvested > 0 or own > 0
        if yielded:
            state = "rendered"
        elif dropped:
            # DEGRADED, and deliberately imprecise. A genuinely empty page
            # with one dropped web font lands here and is a FALSE
            # degradation. The rule errs this way on purpose: S12's
            # asymmetry is that under-claiming coverage is survivable and
            # over-claiming is not. The report says "may not have rendered".
            state = "degraded"
        else:
            state = "rendered"

    return PageResult(state=state, requests=len(urls),
                      dropped_hosts=tuple(sorted(dropped)),
                      in_scope_failures=tuple(sorted(in_scope_failures)),
                      capped=capped, load_errors=failures)


def _failed() -> tuple[PageResult, list[str]]:
    """CONTAINED (Ruling 18): "I could not reach this page" is an ANSWER to
    `visit`'s question, not an exception -- `classify` already has a
    `failed` state for exactly that, so a page `visit` could not reach still
    appears in the crawl's summary instead of vanishing from it.
    """
    return (PageResult(state="failed", requests=0, dropped_hosts=(),
                       in_scope_failures=(), capped=False), [])


def visit(conn: cdp.Connection, url: str, *, page_origins: set[str],
          session_id: str, settle: float = 2.0,
          cap: float = 20.0) -> tuple[PageResult, list[str]]:
    """Navigate, wait for quiet, harvest, judge.

    `session_id` is the page-target session `Browser.__enter__` attached
    (Ruling 9) -- required, not optional, because every call below is a
    `Page`/`Network`/`DOM` domain call and none of those domains exist on
    the browser-level connection `--remote-debugging-pipe` hands us.

    `cap` is what stops one long-polling endpoint, analytics beacon or open
    WebSocket consuming the whole crawl budget. A page that hits it is
    recorded as CAPPED, not as complete -- capped and complete are different
    claims and the summary keeps them apart.

    RULING 18 -- one page's failure must not end the crawl, but a dead
    browser must. `cdp.CdpError` (and its `CdpTimeout` sibling, where not
    already given a more specific meaning below) is CONTAINED here as a
    `failed` `PageResult`: `crawl()` calls `visit` with no guard of its own,
    on purpose, because the guard belongs to the question `visit` answers,
    not to the loop that asks it. `cdp.CdpClosed` means the browser itself
    is gone -- every later page would fail the identical way, so it
    PROPAGATES uncaught. Each `except` below lists `CdpClosed` before the
    general `CdpError` it is a subclass of, so a dead browser is never
    caught by the broader clause and reported as one more failed page.
    """
    try:
        conn.call("Network.enable", session_id=session_id)
        conn.call("Page.enable", session_id=session_id)
        # THE DOMAIN THAT WAS MISSING. `Log` costs nothing and carries the
        # one signal that separates "this page had little to offer" from
        # "this page could not load itself" -- see `_LOAD_FAILURE_MARKERS`.
        conn.call("Log.enable", session_id=session_id)
    except cdp.CdpClosed:
        raise
    except cdp.CdpError:
        return _failed()
    conn.drain(timeout=0.0)

    events: list[dict] = []
    capped = False
    try:
        conn.call("Page.navigate", {"url": url}, session_id=session_id,
                  timeout=cap)
    except cdp.CdpTimeout:
        # A slow navigation is not a failed page -- the settle loop below
        # still collects whatever the page produced before the cap, and
        # `capped` keeps that distinct from a complete visit.
        capped = True
    except cdp.CdpClosed:
        raise
    except cdp.CdpError:
        return _failed()

    deadline = time.monotonic() + cap
    quiet_since = None
    while time.monotonic() < deadline:
        batch = conn.drain(timeout=0.25)
        events.extend(batch)
        if batch:
            quiet_since = None
        else:
            quiet_since = quiet_since or time.monotonic()
            if time.monotonic() - quiet_since >= settle:
                break
    else:
        capped = True

    html = ""
    try:
        root = conn.call("DOM.getDocument", {"depth": -1},
                         session_id=session_id, timeout=cap)
        node_id = root.get("root", {}).get("nodeId")
        if node_id:
            html = conn.call("DOM.getOuterHTML", {"nodeId": node_id},
                             session_id=session_id,
                             timeout=cap).get("outerHTML", "")
    except cdp.CdpClosed:
        raise
    except cdp.CdpError:
        # A document we cannot read is a page we harvested nothing from --
        # which `classify` will read as no yield, and that is honest. This
        # is narrower than the whole-page failure above: the events already
        # collected are still real and still classified.
        #
        # DELIBERATELY NOT `_failed()` here, unlike the two guards above --
        # and this is the whole asymmetry, not an inconsistency to tidy up.
        # By this point the network events have already been collected: we
        # know what the page requested. Reporting `failed` would discard
        # that real signal in favour of a weaker claim. Letting `classify`
        # judge on the events alone (in-scope requests seen -> `rendered`;
        # nothing, plus drops -> `degraded`) is strictly more informative,
        # and S12's preference is always the most specific true statement
        # available. The other two sites fail BEFORE any signal exists;
        # this one fails AFTER. That is the whole asymmetry.
        html = ""

    links = harvest(html, url) if html else []
    result = classify(events, page_origins=page_origins,
                      harvested=len(links), capped=capped)
    return result, [u for u in (normalise(x) for x in links) if u]
